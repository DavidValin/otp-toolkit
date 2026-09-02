/*
 * otp_firewall.c - OTP_TOOLKIT_FIREWALL kernel-side packet interception.
 *
 * Deliberately thin: this module never touches packet payload bytes, does
 * no crypto and no file I/O. Its only job is a fast in-kernel "is this
 * source/destination IP a keychain contact" check, and handing candidate
 * packets to userspace (otp-firewalld) via the standard NFQUEUE verdict -
 * the actual trial-decryption, packet growth/shrink and checksum work all
 * happen there, reusing the existing (unmodified) otp cipher/keychain
 * library. See README.md in this directory ("Architecture") for the full design and why it's split
 * this way.
 *
 * Scope (v1): hooks are registered only in
 * init_net (no per-namespace/container support), and only TCP/UDP over
 * IPv4/IPv6 are considered - every other IP protocol is dropped while
 * enabled, except ICMPv6 (Neighbor Discovery, MLD, PMTU/error signaling),
 * which is always allowed through - see otp_fw_is_icmpv6() below. IPv6
 * extension headers are not walked.
 *
 * A non-first IP fragment carries no L4 header of its own - just a raw
 * continuation of the original packet's payload - so otp_fw_extract()
 * (which unconditionally reads a struct tcphdr/udphdr right after the IP
 * header) would misparse one if it ever reached PRE_ROUTING unreassembled.
 * Rather than teach the parser about fragmentation, otp_firewall_init()
 * requires IP defragmentation to run before this module's own hooks do
 * (nf_defrag_ipv4_enable()/nf_defrag_ipv6_enable(), the standard kernel
 * API other in-tree users of raw packet data - nf_conntrack, IPVS,
 * br_netfilter - rely on for the same reason) - PRE_ROUTING never sees a
 * fragment at all once that's active, only fully reassembled packets.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ipv6.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/mm.h> /* kvmalloc()/kvfree() */
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/atomic.h>
#include <net/net_namespace.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>

#include "otp_firewall.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("David Valin <hola@davidvalin.com>");
MODULE_DESCRIPTION("OTP_TOOLKIT_FIREWALL - kernel-side packet interception (see README.md in this directory)");

static ushort queue_egress = 0;
static ushort queue_ingress = 1;
module_param(queue_egress, ushort, 0444);
module_param(queue_ingress, ushort, 0444);
MODULE_PARM_DESC(queue_egress, "NFQUEUE number for outbound (candidate) packets");
MODULE_PARM_DESC(queue_ingress, "NFQUEUE number for inbound (candidate) packets");

/* Starts disabled: an operator must explicitly enable enforcement after
 * loading (write "1" to /proc/otp_firewall/enabled), matching the
 * documented kill-switch safety posture - insmod alone never starts
 * blocking traffic. */
static atomic_t g_enabled = ATOMIC_INIT(0);

struct otp_fw_candidate
{
  u8 family; /* AF_INET or AF_INET6 */
  union
  {
    __be32 v4;
    struct in6_addr v6;
  } addr;
};

static struct otp_fw_candidate g_candidates[OTP_FW_MAX_CANDIDATES];
static int g_candidate_count;
static DEFINE_RWLOCK(g_candidates_lock);

static int otp_fw_is_candidate(u8 family, __be32 v4, const struct in6_addr *v6)
{
  int i, found = 0;
  read_lock_bh(&g_candidates_lock);
  for (i = 0; i < g_candidate_count; i++)
  {
    if (g_candidates[i].family != family)
      continue;
    if (family == AF_INET)
    {
      if (g_candidates[i].addr.v4 == v4)
      {
        found = 1;
        break;
      }
    }
    else
    {
      if (ipv6_addr_equal(&g_candidates[i].addr.v6, v6))
      {
        found = 1;
        break;
      }
    }
  }
  read_unlock_bh(&g_candidates_lock);
  return found;
}

/* ICMPv6 carries IPv6's Neighbor Discovery Protocol (router/neighbor
 * solicitation and advertisement, redirects), Multicast Listener
 * Discovery, and path-MTU-discovery/error signaling - none of it
 * application data, all of it required just for IPv6 to work on the
 * local link at all (the rough equivalent of ARP). Unlike TCP/UDP it
 * carries nothing for OTP trial-decryption to authenticate, so rather
 * than drop it like every other non-TCP/UDP protocol (see the
 * module-level scope comment), it is unconditionally exempted - the same
 * treatment essentially every real firewall gives ICMP/ICMPv6 control
 * traffic. IPv4 has no equivalent exemption: ARP is a distinct
 * ethertype that never reaches an IP-family netfilter hook in the first
 * place. */
static int otp_fw_is_icmpv6(struct sk_buff *skb)
{
  struct ipv6hdr *ip6h;
  if (skb->protocol != htons(ETH_P_IPV6))
    return 0;
  if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
    return 0;
  ip6h = ipv6_hdr(skb);
  return ip6h->nexthdr == IPPROTO_ICMPV6;
}

/* Ack-port traffic (firewall/daemon/ack.h's delivery-acknowledgment
 * side channel) must never be routed through the encrypt/decrypt
 * pipeline - it's this daemon's own control traffic, not application
 * data, the same reasoning as the ICMPv6 exemption above. A single
 * "destination UDP port == OTP_FW_ACK_PORT" check identifies it
 * correctly in BOTH directions without needing to distinguish egress
 * from ingress: an outbound ack/redeliver packet this daemon sends is
 * always addressed TO the peer's OTP_FW_ACK_PORT (ack.c's
 * send_datagram() lets the OS pick an ephemeral source port, never
 * OTP_FW_ACK_PORT itself), and an inbound one is, by definition,
 * addressed to this daemon's own listening socket on that same port. */
static int otp_fw_is_ack_port(struct sk_buff *skb)
{
  __be16 dest_port;

  if (skb->protocol == htons(ETH_P_IP))
  {
    struct iphdr *iph;
    struct udphdr *uh;
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
      return 0;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP)
      return 0;
    if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)))
      return 0;
    /* pskb_may_pull() can reallocate skb->data - re-resolve iph rather
     * than trust the pointer obtained before this second pull, the same
     * caution otp_fw_extract() takes by only ever pulling once per
     * branch (this function needs two: header-length-dependent UDP
     * offset isn't known until the IP header itself has been read). */
    iph = ip_hdr(skb);
    uh = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    dest_port = uh->dest;
  }
  else if (skb->protocol == htons(ETH_P_IPV6))
  {
    struct ipv6hdr *ip6h;
    struct udphdr *uh;
    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
      return 0;
    ip6h = ipv6_hdr(skb);
    if (ip6h->nexthdr != IPPROTO_UDP)
      return 0;
    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
      return 0;
    ip6h = ipv6_hdr(skb); /* re-resolve, see the IPv4 branch's comment */
    uh = (struct udphdr *)((unsigned char *)ip6h + sizeof(struct ipv6hdr));
    dest_port = uh->dest;
  }
  else
  {
    return 0;
  }

  return dest_port == htons(OTP_FW_ACK_PORT);
}

/* dir_egress: 1 to extract the destination address (outbound hook), 0
 * for the source address (inbound hook). Returns 1 with *family/*v4/*v6
 * filled for a parsable TCP/UDP IPv4/IPv6 packet, 0 otherwise (caller
 * drops - see the module-level comment on v1 scope). */
static int otp_fw_extract(struct sk_buff *skb, int dir_egress, u8 *family,
                          __be32 *v4, struct in6_addr *v6)
{
  if (skb->protocol == htons(ETH_P_IP))
  {
    struct iphdr *iph;
    if (!pskb_may_pull(skb, sizeof(struct iphdr)))
      return 0;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
      return 0;
    *family = AF_INET;
    *v4 = dir_egress ? iph->daddr : iph->saddr;
    return 1;
  }
  if (skb->protocol == htons(ETH_P_IPV6))
  {
    struct ipv6hdr *ip6h;
    if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
      return 0;
    ip6h = ipv6_hdr(skb);
    if (ip6h->nexthdr != IPPROTO_TCP && ip6h->nexthdr != IPPROTO_UDP)
      return 0;
    *family = AF_INET6;
    *v6 = dir_egress ? ip6h->daddr : ip6h->saddr;
    return 1;
  }
  return 0;
}

/* Builds the NFQUEUE verdict by hand rather than using the kernel's
 * NF_QUEUE_NR() helper: that helper sets NF_VERDICT_FLAG_QUEUE_BYPASS,
 * which silently ACCEPTs a candidate packet if no userspace listener has
 * opened this queue number (e.g. otp-firewalld isn't running yet, or
 * crashed). For a default-deny firewall that is the wrong failure mode -
 * a candidate packet with nothing to validate it must fail closed
 * (dropped), not bypass straight through. */
static inline unsigned int otp_fw_queue_verdict(u16 queue_num)
{
  return (((u32)queue_num) << 16) | NF_QUEUE;
}

static unsigned int otp_fw_hook_egress(void *priv, struct sk_buff *skb,
                                       const struct nf_hook_state *state)
{
  u8 family;
  __be32 v4 = 0;
  struct in6_addr v6;

  (void)priv;
  if (!atomic_read(&g_enabled))
    return NF_ACCEPT;
  if (state->out && (state->out->flags & IFF_LOOPBACK))
    return NF_ACCEPT;
  if (otp_fw_is_icmpv6(skb))
    return NF_ACCEPT;
  if (otp_fw_is_ack_port(skb))
    return NF_ACCEPT;
  if (!otp_fw_extract(skb, 1, &family, &v4, &v6))
    return NF_DROP;
  if (otp_fw_is_candidate(family, v4, &v6))
    return otp_fw_queue_verdict(queue_egress);
  return NF_DROP;
}

static unsigned int otp_fw_hook_ingress(void *priv, struct sk_buff *skb,
                                        const struct nf_hook_state *state)
{
  u8 family;
  __be32 v4 = 0;
  struct in6_addr v6;

  (void)priv;
  if (!atomic_read(&g_enabled))
    return NF_ACCEPT;
  if (state->in && (state->in->flags & IFF_LOOPBACK))
    return NF_ACCEPT;
  if (otp_fw_is_icmpv6(skb))
    return NF_ACCEPT;
  if (otp_fw_is_ack_port(skb))
    return NF_ACCEPT;
  if (!otp_fw_extract(skb, 0, &family, &v4, &v6))
    return NF_DROP;
  if (otp_fw_is_candidate(family, v4, &v6))
    return otp_fw_queue_verdict(queue_ingress);
  return NF_DROP;
}

/* One pair of hook functions, registered separately per IP version
 * (NFPROTO_IPV4 / NFPROTO_IPV6) rather than once under NFPROTO_INET:
 * whether a single NFPROTO_INET registration reliably fans out to both
 * v4 and v6 traffic at the core netfilter dispatch level (as opposed to
 * being an nf_tables-layer convention only) isn't something this could
 * be verified against actual kernel source in the environment this was
 * written in - registering explicitly per family is unambiguous,
 * well-documented behavior with no such uncertainty. */
static struct nf_hook_ops g_hook_ops[4];

/* ---- /proc/otp_firewall/enabled --------------------------------------- */

static ssize_t enabled_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
  char tmp[4];
  int len = snprintf(tmp, sizeof(tmp), "%d\n", atomic_read(&g_enabled) ? 1 : 0);
  (void)f;
  return simple_read_from_buffer(buf, count, ppos, tmp, len);
}

static ssize_t enabled_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
  char tmp[8];
  size_t n = count < sizeof(tmp) - 1 ? count : sizeof(tmp) - 1;
  (void)f;
  (void)ppos;
  if (copy_from_user(tmp, buf, n))
    return -EFAULT;
  tmp[n] = '\0';
  atomic_set(&g_enabled, tmp[0] == '1' ? 1 : 0);
  return (ssize_t)count;
}

static const struct proc_ops enabled_fops = {
   .proc_read = enabled_read,
   .proc_write = enabled_write,
   .proc_lseek = default_llseek,
};

/* ---- /proc/otp_firewall/candidates ------------------------------------- */

static ssize_t candidates_write(struct file *f, const char __user *buf, size_t count, loff_t *ppos)
{
  char *kbuf;
  char *line, *rest;
  struct otp_fw_candidate *staged;
  int staged_count = 0;

  (void)f;
  (void)ppos;
  if (count == 0)
  {
    /* An explicit zero-length write is how the daemon clears the table
     * back to empty (e.g. the last configured contact was just
     * removed) - treating it as a no-op here would mean the table could
     * never be cleared once anything had ever been pushed to it, and
     * the kernel would keep queuing packets for IPs nothing configures
     * anymore. */
    write_lock_bh(&g_candidates_lock);
    g_candidate_count = 0;
    write_unlock_bh(&g_candidates_lock);
    return 0;
  }
  /* Sized to cover the daemon's own worst case (OTP_FW_MAX_CONFIG_ENTRIES
   * unique IPs, each up to OTP_FW_IPSTR_LEN+1 bytes as text - up to
   * ~1.9MB), with headroom, rather than an arbitrary round number: a cap
   * below what a legitimately large config could need would reject the
   * push outright, leaving the candidate table at its previous (possibly
   * empty) state instead of just truncating the entries past
   * OTP_FW_MAX_CANDIDATES (which is handled gracefully below). */
  if (count > 4 << 20)
    return -EMSGSIZE;

  /* kvmalloc rather than kmalloc: this can now be multiple MB, too large
   * to reliably rely on kmalloc's physically-contiguous allocation
   * succeeding under memory pressure. kvmalloc falls back to vmalloc
   * automatically when a contiguous chunk that size isn't available. */
  kbuf = kvmalloc(count + 1, GFP_KERNEL);
  if (!kbuf)
    return -ENOMEM;
  if (copy_from_user(kbuf, buf, count))
  {
    kvfree(kbuf);
    return -EFAULT;
  }
  kbuf[count] = '\0';

  staged = kmalloc_array(OTP_FW_MAX_CANDIDATES, sizeof(*staged), GFP_KERNEL);
  if (!staged)
  {
    kvfree(kbuf);
    return -ENOMEM;
  }

  rest = kbuf;
  while ((line = strsep(&rest, "\n")) != NULL)
  {
    __be32 v4;
    struct in6_addr v6;
    const char *end;

    while (*line == ' ' || *line == '\t' || *line == '\r')
      line++;
    if (*line == '\0')
      continue;
    if (staged_count >= OTP_FW_MAX_CANDIDATES)
    {
      /* write()'s return value only reports bytes consumed, not a rich
       * error protocol, so there's no way to signal this back to the
       * daemon over the syscall itself - surfacing it in dmesg is the
       * idiomatic kernel way to make a silent truncation visible at
       * all. */
      pr_warn("otp_firewall: candidates list exceeds %d entries, truncating\n",
             OTP_FW_MAX_CANDIDATES);
      break;
    }

    if (in4_pton(line, -1, (u8 *)&v4, -1, &end) == 1)
    {
      staged[staged_count].family = AF_INET;
      staged[staged_count].addr.v4 = v4;
      staged_count++;
    }
    else if (in6_pton(line, -1, (u8 *)&v6, -1, &end) == 1)
    {
      staged[staged_count].family = AF_INET6;
      staged[staged_count].addr.v6 = v6;
      staged_count++;
    }
    /* Unparsable lines are skipped: userspace already validated
     * addresses via inet_ntop() before writing them here, so this is
     * defensive, not the primary validation. */
  }
  kvfree(kbuf);

  write_lock_bh(&g_candidates_lock);
  memcpy(g_candidates, staged, (size_t)staged_count * sizeof(*staged));
  g_candidate_count = staged_count;
  write_unlock_bh(&g_candidates_lock);

  kfree(staged);
  return (ssize_t)count;
}

static const struct proc_ops candidates_fops = {
   .proc_write = candidates_write,
};

static struct proc_dir_entry *g_proc_dir;

static int __init otp_firewall_init(void)
{
  int rc;

  g_proc_dir = proc_mkdir(OTP_FW_PROC_DIR, NULL);
  if (!g_proc_dir)
    return -ENOMEM;
  if (!proc_create(OTP_FW_PROC_ENABLED_NAME, 0600, g_proc_dir, &enabled_fops) ||
     !proc_create(OTP_FW_PROC_CANDIDATES_NAME, 0200, g_proc_dir, &candidates_fops))
  {
    remove_proc_subtree(OTP_FW_PROC_DIR, NULL);
    return -ENOMEM;
  }

  /* Required, not best-effort: without this, PRE_ROUTING can see raw,
   * unreassembled fragments (see the module-level comment above), which
   * otp_fw_extract() cannot safely parse. Refusing to load rather than
   * running degraded matches this module's fail-closed posture
   * elsewhere (e.g. otp_fw_queue_verdict()). Depends on the standard
   * nf_defrag_ipv4/nf_defrag_ipv6 modules being loadable - `modprobe
   * nf_defrag_ipv4 nf_defrag_ipv6` first if insmod reports them as
   * unresolved symbols; see README.md in this directory's "Activate" section. */
  rc = nf_defrag_ipv4_enable(&init_net);
  if (rc)
  {
    pr_err("otp_firewall: nf_defrag_ipv4_enable failed (%d) - refusing to load\n", rc);
    remove_proc_subtree(OTP_FW_PROC_DIR, NULL);
    return rc;
  }
  rc = nf_defrag_ipv6_enable(&init_net);
  if (rc)
  {
    pr_err("otp_firewall: nf_defrag_ipv6_enable failed (%d) - refusing to load\n", rc);
    nf_defrag_ipv4_disable(&init_net);
    remove_proc_subtree(OTP_FW_PROC_DIR, NULL);
    return rc;
  }

  g_hook_ops[0].hook = otp_fw_hook_egress;
  g_hook_ops[0].pf = NFPROTO_IPV4;
  g_hook_ops[0].hooknum = NF_INET_POST_ROUTING;
  g_hook_ops[0].priority = NF_IP_PRI_LAST;

  g_hook_ops[1].hook = otp_fw_hook_egress;
  g_hook_ops[1].pf = NFPROTO_IPV6;
  g_hook_ops[1].hooknum = NF_INET_POST_ROUTING;
  g_hook_ops[1].priority = NF_IP6_PRI_LAST;

  g_hook_ops[2].hook = otp_fw_hook_ingress;
  g_hook_ops[2].pf = NFPROTO_IPV4;
  g_hook_ops[2].hooknum = NF_INET_PRE_ROUTING;
  g_hook_ops[2].priority = NF_IP_PRI_RAW; /* before conntrack - see README.md in this directory's "Architecture" section */

  g_hook_ops[3].hook = otp_fw_hook_ingress;
  g_hook_ops[3].pf = NFPROTO_IPV6;
  g_hook_ops[3].hooknum = NF_INET_PRE_ROUTING;
  g_hook_ops[3].priority = NF_IP6_PRI_RAW;

  for (rc = 0; rc < 4; rc++)
  {
    int err = nf_register_net_hook(&init_net, &g_hook_ops[rc]);
    if (err)
    {
      while (--rc >= 0)
        nf_unregister_net_hook(&init_net, &g_hook_ops[rc]);
      nf_defrag_ipv6_disable(&init_net);
      nf_defrag_ipv4_disable(&init_net);
      remove_proc_subtree(OTP_FW_PROC_DIR, NULL);
      return err;
    }
  }

  pr_info("otp_firewall: loaded, disabled by default - write 1 to /proc/%s/%s to enable\n",
         OTP_FW_PROC_DIR, OTP_FW_PROC_ENABLED_NAME);
  return 0;
}

static void __exit otp_firewall_exit(void)
{
  int i;
  for (i = 3; i >= 0; i--)
    nf_unregister_net_hook(&init_net, &g_hook_ops[i]);
  nf_defrag_ipv6_disable(&init_net);
  nf_defrag_ipv4_disable(&init_net);
  remove_proc_subtree(OTP_FW_PROC_DIR, NULL);
  pr_info("otp_firewall: unloaded\n");
}

module_init(otp_firewall_init);
module_exit(otp_firewall_exit);
