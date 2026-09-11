/*
 * otpfw.c - REAL DESTINATION: sys/net/otpfw.c in your OpenBSD kernel
 * source tree (see ../README.md's "Kernel integration"). Statically
 * compiled into the kernel (no loadable-module mechanism exists on
 * modern OpenBSD - see ../README.md's "Why this is a kernel patch,
 * not a loadable module"), controlled by a `pseudo-device otpfw` config
 * line (build-time: is this compiled in at all) and a /dev/otpfw ioctl
 * kill switch (runtime: is it currently enforcing).
 *
 * Modeled throughout on bpf.c's shape (sys/net/bpf.c) - the closest
 * existing in-tree precedent for "a pseudo-device that hands whole
 * packets to a userspace process and takes a verdict/response back",
 * right down to reusing its four-entry-point cdevsw layout
 * (open/close/read/write) plus ioctl for control operations. All
 * crypto/keychain logic stays in userspace (otp_firewalld) - this file
 * never touches cipher.c or the keychain, same as every other platform's
 * kernel-side code.
 *
 * CONFIDENCE, read before trusting any part of this file - see
 * ../README.md's Status section for the full, ranked list. Short
 * version: the character device read/write/ioctl data path, the
 * candidate table, and the kill switch are ordinary, well-documented
 * kernel-driver patterns (highest confidence, same class as FreeBSD's
 * cdevsw). The mbuf reconstruction/reinjection calls
 * (ip_output()/ip_input() called recursively) and the exact tsleep/mbuf
 * KPI signatures used throughout are this file's biggest open questions
 * - this was written without a real OpenBSD kernel source tree or
 * header set to check any of it against.
 *
 * Only one process may hold /dev/otpfw open at a time (see
 * otpfwopen()) - deliberate, not an oversight: otpfwread()/otpfwwrite()
 * stage each packet/verdict in a function-local `static` buffer (too
 * large for a kernel stack frame), which is only safe because exactly
 * one otp_firewalld instance is ever expected to be talking to this
 * device, the same assumption the userspace daemon itself already makes
 * (it has no cross-instance coordination of its own either). A second
 * concurrent opener would otherwise be able to race those buffer fills
 * against each other and splice one packet's data with another's
 * verdict.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/mutex.h>
#include <sys/uio.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet6/ip6_var.h>

#include "otpfwvar.h"
#include "otp_firewall_proto.h"

/* ------------------------------------------------------------------ */
/* Candidate IP table - rwlock-protected flat array, read far more      */
/* often (every candidate packet) than written (only when otp_firewalld */
/* reloads firewall.config) - same flat-array-under-a-lock tradeoff      */
/* every other platform's kernel-side candidate table makes: realistic   */
/* firewall.config sizes are dwarfed by per-packet parsing cost either   */
/* way.                                                                  */
/* ------------------------------------------------------------------ */

struct rwlock otpfw_cand_lock = RWLOCK_INITIALIZER("otpfwcand");
otp_fw_candidate_t *otpfw_candidates; /* M_DEVBUF, OTP_FW_WIRE_MAX_CANDIDATES capacity */
uint32_t otpfw_candidate_count;

static int
otpfw_is_candidate(uint8_t is_v6, const uint8_t *addr)
{
  int found = 0;
  size_t addr_len = is_v6 ? 16 : 4;

  rw_enter_read(&otpfw_cand_lock);
  for (uint32_t i = 0; i < otpfw_candidate_count; i++)
  {
    if (otpfw_candidates[i].is_v6 != is_v6)
      continue;
    if (memcmp(otpfw_candidates[i].addr, addr, addr_len) == 0)
    {
      found = 1;
      break;
    }
  }
  rw_exit_read(&otpfw_cand_lock);
  return found;
}

static int
otpfw_set_candidates(const otp_fw_candidate_t *list, uint32_t count)
{
  if (count > OTP_FW_WIRE_MAX_CANDIDATES)
    return EINVAL;

  rw_enter_write(&otpfw_cand_lock);
  if (count > 0)
    memcpy(otpfw_candidates, list, count * sizeof(otp_fw_candidate_t));
  otpfw_candidate_count = count;
  rw_exit_write(&otpfw_cand_lock);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Kill switch - the runtime on/off toggle otpfwctl actually uses day    */
/* to day (see ../README.md's "Activate"/"Deactivate"). Separate      */
/* from NOTPFW (see otpfwvar.h): NOTPFW decides whether this code exists */
/* in the kernel binary at all (a rebuild+reboot decision), this decides */
/* whether it's currently doing anything (instant, no reboot).           */
/* ------------------------------------------------------------------ */

static struct mutex otpfw_enabled_lock = MUTEX_INITIALIZER(IPL_NET);
static int otpfw_enabled = 0; /* starts disabled - matches every other platform's default-off posture at boot */

/* ------------------------------------------------------------------ */
/* Pending-packet queue: mbufs consumed by a hook call, waiting for a   */
/* userspace verdict. tsleep_nsec()/wakeup() on &otpfw_ready_queue is    */
/* the OpenBSD-idiomatic equivalent of FreeBSD's cv_wait()/cv_signal()   */
/* here - a blocked read() sleeps until a packet is queued or the        */
/* device is being torn down.                                            */
/*                                                                        */
/* Unlike the FreeBSD port's otp_fw_pending (which - see its own          */
/* README's Status section - reuses a single TAILQ_ENTRY for both the    */
/* ready queue and the in-flight-by-packet_id table, a documented,       */
/* deliberately-left-in bug), this struct uses two separate TAILQ_ENTRY   */
/* fields from the start: nothing about this design needs that shortcut, */
/* and there's no reason to reproduce a known bug just because an         */
/* earlier port has one.                                                 */
/*                                                                        */
/* otpfw_queued_count/OTPFW_MAX_QUEUED bound how many `struct              */
/* otpfw_pending` (each ~70KB - dominated by OTP_FW_MAX_PACKET) can be     */
/* outstanding at once: without a cap, a stalled or crashed                */
/* otp_firewalld (the only thing that ever drains these queues) combined   */
/* with continued matching traffic would grow kernel memory usage          */
/* without bound - a memory-exhaustion DoS with no fail-closed cutoff.     */
/* Once the cap is hit, new candidate packets are simply dropped (the      */
/* same default-deny posture every other rejection reason in this file     */
/* already has) rather than queued.                                       */
/* ------------------------------------------------------------------ */

#define OTPFW_MAX_QUEUED 4096

struct otpfw_pending
{
  TAILQ_ENTRY(otpfw_pending) pend_ready_link;
  TAILQ_ENTRY(otpfw_pending) pend_inflight_link;
  uint64_t packet_id;
  otp_fw_pkt_direction_t direction;
  int family; /* AF_INET or AF_INET6 - which reinjection path to use on verdict */
  unsigned int rcvif_index; /* ingress only: the interface the packet arrived on, restored on reinject via ip_input() - 0 if not applicable */
  uint32_t data_len;
  uint8_t data[OTP_FW_MAX_PACKET];
};

static struct mutex otpfw_queue_lock = MUTEX_INITIALIZER(IPL_NET);
static TAILQ_HEAD(, otpfw_pending) otpfw_ready_queue = TAILQ_HEAD_INITIALIZER(otpfw_ready_queue);
static TAILQ_HEAD(, otpfw_pending) otpfw_inflight_queue = TAILQ_HEAD_INITIALIZER(otpfw_inflight_queue);
static uint64_t otpfw_next_packet_id = 1;
static uint32_t otpfw_queued_count = 0; /* number of live otpfw_pending allocations - see OTPFW_MAX_QUEUED above */
static int otpfw_device_closing = 0;
static int otpfw_device_is_open = 0; /* single-open enforced - see the file header */

/* Frees every node still on either queue (a daemon close/restart while
 * traffic was in flight - see otpfwclose()) - without this, each such
 * node simply leaks: nothing else ever frees a node that a new daemon
 * instance's read()/write() calls can no longer reach, since packet_ids
 * are not preserved across a close. Must be called with otpfw_queue_lock
 * held. */
static void
otpfw_drain_queues_locked(void)
{
  struct otpfw_pending *p, *tmp;

  TAILQ_FOREACH_SAFE(p, &otpfw_ready_queue, pend_ready_link, tmp)
    TAILQ_REMOVE(&otpfw_ready_queue, p, pend_ready_link);

  TAILQ_FOREACH_SAFE(p, &otpfw_inflight_queue, pend_inflight_link, tmp)
  {
    TAILQ_REMOVE(&otpfw_inflight_queue, p, pend_inflight_link);
    free(p, M_DEVBUF, sizeof(*p));
    otpfw_queued_count--;
  }
}

static struct otpfw_pending *
otpfw_find_inflight_locked(uint64_t packet_id)
{
  struct otpfw_pending *p;
  TAILQ_FOREACH(p, &otpfw_inflight_queue, pend_inflight_link)
  {
    if (p->packet_id == packet_id)
      return p;
  }
  return NULL;
}

/* ------------------------------------------------------------------ */
/* Loop avoidance: an mbuf tag (m_tag_get()/m_tag_find()/m_tag_delete()) */
/* rather than a shared, ambiguous-meaning flag bit - the kernel's own   */
/* general mechanism for attaching transient, subsystem-private          */
/* metadata to one packet without risking collision with unrelated code  */
/* (this is exactly what pf itself uses PACKET_TAG_PF_* tags for its own */
/* loop-avoidance/state marking, rather than an mbuf flag). Genuinely     */
/* more appropriate than reusing a flag bit like FreeBSD's                */
/* M_SKIP_FIREWALL/M_PROTO1-class bits - see ../README.md's Status        */
/* section for what's still unverified about the exact m_tag_* call       */
/* shapes used here. OTPFW_MTAG_REINJECTED is deliberately a large,       */
/* distinctive value rather than a small integer, to minimize the chance  */
/* of colliding with an in-tree PACKET_TAG_* constant this port has no    */
/* way to enumerate without real headers.                                */
/* ------------------------------------------------------------------ */

#define OTPFW_MTAG_REINJECTED 0x4f545046 /* "OTPF" */

/* Marks `m` as already-vetted before a verdict reinjects it - see
 * otpfw_apply_verdict(). Best-effort: if the tag allocation itself fails
 * (M_NOWAIT, under memory pressure), `m` is reinjected unmarked rather
 * than dropped outright - the realistic worst case is one extra,
 * otherwise-harmless trip back through this hook on its next pass
 * (it will re-parse as ordinary candidate traffic and get re-queued to
 * otp_firewalld, which is wasteful but not unsafe), not a crash or a
 * silently-lost packet. */
static void
otpfw_mark_reinjected(struct mbuf *m)
{
  struct m_tag *t = m_tag_get(OTPFW_MTAG_REINJECTED, 0, M_NOWAIT);
  if (t)
    m_tag_prepend(m, t);
}

/* Returns 1 and strips the tag if `m` was already vetted (see
 * otpfw_mark_reinjected()), 0 otherwise. */
static int
otpfw_take_reinjected(struct mbuf *m)
{
  struct m_tag *t = m_tag_find(m, OTPFW_MTAG_REINJECTED, NULL);
  if (!t)
    return 0;
  m_tag_delete(m, t);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Hook core: fast candidate/ICMPv6/ack-port check, then consume-and-    */
/* queue. dir_out: 1 for otpfw_hook_out() (destination address is what   */
/* matters for candidate selection), 0 for otpfw_hook_in() (source        */
/* address matters). Mirrors otp_fw_extract()/otp_fw_hook() on Linux/     */
/* FreeBSD - same v1 scope limit (TCP/UDP only, no IPv6 extension header  */
/* walking).                                                              */
/* ------------------------------------------------------------------ */

static int
otpfw_is_icmpv6(struct mbuf *m)
{
  struct ip6_hdr *ip6;
  if (m->m_len < (int)sizeof(struct ip6_hdr))
    return 0; /* caller already pulled up enough for a v6 header before calling this */
  ip6 = mtod(m, struct ip6_hdr *);
  return ip6->ip6_nxt == IPPROTO_ICMPV6;
}

/* Same three-way pullup-may-free-or-replace-the-chain contract as the
 * FreeBSD port's otp_fw_is_ack_port() - see that function's doc comment
 * for the full reasoning; identical here since m_pullup()'s contract is
 * shared BSD mbuf API, not FreeBSD-specific. */
static int
otpfw_is_ack_port(struct mbuf **mp, size_t ip_hdr_len)
{
  struct mbuf *pulled = m_pullup(*mp, ip_hdr_len + sizeof(struct udphdr));
  if (!pulled)
  {
    *mp = NULL;
    return -1;
  }
  *mp = pulled;
  struct udphdr *uh = (struct udphdr *)(mtod(pulled, uint8_t *) + ip_hdr_len);
  return (uh->uh_dport == htons(OTP_FW_ACK_PORT)) ? 1 : 0;
}

static int
otpfw_hook(struct mbuf **mp, struct ifnet *ifp, int dir_out)
{
  struct mbuf *m = *mp;
  int is_v6;

  if (otpfw_take_reinjected(m))
  {
    /* Our own reinjected packet, on its second pass through this same
     * hook - see the OTPFW_MTAG_REINJECTED note above. Let it through
     * without re-evaluating it. */
    return 0;
  }

  mtx_enter(&otpfw_enabled_lock);
  int enabled = otpfw_enabled;
  mtx_leave(&otpfw_enabled_lock);
  if (!enabled)
    return 0; /* fail-open passthrough while disabled */

  if (m->m_pkthdr.len < (int)sizeof(struct ip))
    return 0; /* too short to be IP at all - not this firewall's problem */

  m = m_pullup(m, sizeof(struct ip));
  if (!m)
  {
    *mp = NULL;
    return 1; /* mbuf chain is gone - treat as consumed/dropped, same as every other failure path below */
  }
  struct ip *iph = mtod(m, struct ip *);
  is_v6 = (iph->ip_v == 6);

  uint8_t addr[16];
  memset(addr, 0, sizeof(addr));
  int family;

  if (is_v6)
  {
    m = m_pullup(m, sizeof(struct ip6_hdr));
    if (!m)
    {
      *mp = NULL;
      return 1;
    }
    struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
    if (otpfw_is_icmpv6(m))
    {
      *mp = m;
      return 0; /* Neighbor Discovery etc. always exempted, see ../README.md */
    }
    if (ip6->ip6_nxt != IPPROTO_TCP && ip6->ip6_nxt != IPPROTO_UDP)
    {
      m_freem(m);
      *mp = NULL;
      return 1; /* default-deny: not TCP/UDP and not the ICMPv6 exemption */
    }
    if (ip6->ip6_nxt == IPPROTO_UDP)
    {
      int ack_rc = otpfw_is_ack_port(&m, sizeof(struct ip6_hdr));
      if (ack_rc < 0)
      {
        *mp = NULL;
        return 1;
      }
      if (ack_rc == 1)
      {
        *mp = m;
        return 0; /* see otpfw_is_ack_port()'s comment */
      }
      ip6 = mtod(m, struct ip6_hdr *); /* re-derive: otpfw_is_ack_port() may have reallocated m */
    }
    memcpy(addr, dir_out ? &ip6->ip6_dst : &ip6->ip6_src, 16);
    family = AF_INET6;
  }
  else
  {
    if (iph->ip_p != IPPROTO_TCP && iph->ip_p != IPPROTO_UDP)
    {
      m_freem(m);
      *mp = NULL;
      return 1;
    }
    if (iph->ip_p == IPPROTO_UDP)
    {
      int ack_rc = otpfw_is_ack_port(&m, sizeof(struct ip)); /* fixed 20-byte header assumption, matching every other platform's existing IPv4 simplification */
      if (ack_rc < 0)
      {
        *mp = NULL;
        return 1;
      }
      if (ack_rc == 1)
      {
        *mp = m;
        return 0;
      }
      iph = mtod(m, struct ip *); /* re-derive: otpfw_is_ack_port() may have reallocated m */
    }
    uint32_t v4 = dir_out ? iph->ip_dst.s_addr : iph->ip_src.s_addr;
    memcpy(addr, &v4, 4);
    family = AF_INET;
  }

  if (!otpfw_is_candidate(is_v6, addr))
  {
    m_freem(m);
    *mp = NULL;
    return 1; /* no configured contact for this address: default-deny, without ever queuing to userspace */
  }

  if (m->m_pkthdr.len > OTP_FW_MAX_PACKET)
  {
    m_freem(m);
    *mp = NULL;
    return 1; /* pre-check bound: refuse before spending any real work on a packet too big to ever fit the queue buffer */
  }

  struct otpfw_pending *pend = malloc(sizeof(*pend), M_DEVBUF, M_NOWAIT | M_ZERO);
  if (!pend)
  {
    m_freem(m);
    *mp = NULL;
    return 1;
  }
  pend->direction = dir_out ? OTP_FW_PKT_OUTBOUND : OTP_FW_PKT_INBOUND;
  pend->family = family;
  pend->rcvif_index = (!dir_out && m->m_pkthdr.ph_ifidx) ? m->m_pkthdr.ph_ifidx : (ifp ? ifp->if_index : 0);
  pend->data_len = (uint32_t)m->m_pkthdr.len;
  m_copydata(m, 0, m->m_pkthdr.len, pend->data);

  mtx_enter(&otpfw_queue_lock);
  if (otpfw_queued_count >= OTPFW_MAX_QUEUED)
  {
    /* otp_firewalld isn't draining the queue (stalled, dead, or just
     * genuinely overwhelmed) - see OTPFW_MAX_QUEUED's own comment.
     * Drop rather than grow kernel memory without bound. */
    mtx_leave(&otpfw_queue_lock);
    free(pend, M_DEVBUF, sizeof(*pend));
    m_freem(m);
    *mp = NULL;
    return 1;
  }
  pend->packet_id = otpfw_next_packet_id++;
  TAILQ_INSERT_TAIL(&otpfw_inflight_queue, pend, pend_inflight_link);
  TAILQ_INSERT_TAIL(&otpfw_ready_queue, pend, pend_ready_link);
  otpfw_queued_count++;
  wakeup(&otpfw_ready_queue);
  mtx_leave(&otpfw_queue_lock);

  m_freem(m);
  *mp = NULL;
  return 1; /* consumed: pended for an async verdict - caller must stop processing, same as a pf_test() DROP */
}

int
otpfw_hook_out(struct mbuf **mp, struct ifnet *ifp)
{
  return otpfw_hook(mp, ifp, 1);
}

int
otpfw_hook_in(struct mbuf **mp, struct ifnet *ifp)
{
  return otpfw_hook(mp, ifp, 0);
}

/* ------------------------------------------------------------------ */
/* Verdict application: reinject or drop.                               */
/*                                                                       */
/* Reinjection recurses back into ip_output()/ip_input() (declared       */
/* extern here, not in any header this file includes - both are ordinary */
/* non-static kernel-wide symbols) rather than reaching lower for the    */
/* interface's own if_output(): ip_output() re-fragments a grown packet  */
/* if OTP-wrapping pushed it over the path MTU (see ../README.md's       */
/* "Limitations" - "handled by ordinary IP fragmentation"), which would  */
/* be lost by skipping straight to if_output(). otpfw_mark_reinjected()  */
/* is what stops the recursive call from re-entering this same hook a    */
/* second time - see that function's own comment above.                  */
/*                                                                        */
/* THE FOUR PROTOTYPES BELOW ARE THE LEAST CERTAIN PART OF THIS ENTIRE    */
/* FILE - more so than the file header's general KPI disclaimer already   */
/* covers. ip_output()'s argument list is reconstructed from general,     */
/* long-stable BSD networking knowledge (it has looked roughly like this  */
/* across the BSD family for decades) and NOT checked against a real      */
/* current <netinet/ip_var.h>. ip6_input()'s in particular is a genuine   */
/* guess at arity, not just types - some recent OpenBSD network-stack      */
/* work plausibly changed input-path signatures (e.g. to thread through   */
/* additional per-call context for SMP), but this was written with no way */
/* to confirm what that context type is or whether it applies here at     */
/* all, so this deliberately declares the single-argument shape ip_input()*/
/* has always had rather than inventing a second parameter it can't back  */
/* up. Whoever applies this patch against real OpenBSD headers should     */
/* delete these four extern lines entirely and instead pull the real      */
/* prototypes from <netinet/ip_var.h>/<netinet6/ip6_var.h> - they are     */
/* included here only so this file parses standalone for review.          */
/* ------------------------------------------------------------------ */

extern int ip_output(struct mbuf *, struct mbuf *, struct route *, int,
                     struct ip_moptions *, struct inpcb *);
extern int ip6_output(struct mbuf *, struct ip6_pktopts *, struct route *,
                      int, struct ip6_moptions *, struct inpcb *);
extern void ip_input(struct mbuf *);
extern void ip6_input(struct mbuf *);

static void
otpfw_apply_verdict(const otp_fw_verdict_submission_t *v)
{
  mtx_enter(&otpfw_queue_lock);
  struct otpfw_pending *pend = otpfw_find_inflight_locked(v->packet_id);
  if (pend)
  {
    TAILQ_REMOVE(&otpfw_inflight_queue, pend, pend_inflight_link);
    otpfw_queued_count--;
  }
  mtx_leave(&otpfw_queue_lock);

  if (!pend)
    return; /* stale/unknown packet_id - daemon restarted mid-flight, or a duplicate write(); nothing to do */

  if (v->verdict == OTP_FW_VERDICT_DROP)
  {
    free(pend, M_DEVBUF, sizeof(*pend));
    return;
  }

  /* v->data_len is userspace-controlled input to this kernel-mode
   * function - otpfwwrite()'s uio_resid check only bounds the size of
   * the whole fixed-size wire struct, not this field's value. Without
   * this check, an out-of-range data_len here would make m_copyback()
   * below read past the end of v->data[] (a fixed OTP_FW_MAX_PACKET-byte
   * array) and copy adjacent kernel memory into a packet that then gets
   * reinjected onto the network or handed to ip_input() - a real kernel
   * memory disclosure, not just an inert overread. otp_firewalld itself
   * never sends an out-of-range value, but this function must not trust
   * that from kernel mode regardless of who the (root-only, but still
   * userspace) caller is. */
  if (v->verdict == OTP_FW_VERDICT_FORWARD_MODIFIED && v->data_len > OTP_FW_MAX_PACKET)
  {
    free(pend, M_DEVBUF, sizeof(*pend));
    return;
  }

  const uint8_t *send_data = (v->verdict == OTP_FW_VERDICT_FORWARD_MODIFIED) ? v->data : pend->data;
  uint32_t send_len = (v->verdict == OTP_FW_VERDICT_FORWARD_MODIFIED) ? v->data_len : pend->data_len;

  struct mbuf *m = m_gethdr(M_DONTWAIT, MT_DATA);
  if (m)
  {
    m->m_pkthdr.len = 0;
    m_copyback(m, 0, send_len, send_data, M_NOWAIT); /* grows/allocates the chain as needed - see below */

    /* m_copyback()'s success is not checked here - not something this
     * port could confirm the failure-signaling convention for (void
     * return vs. int, or none at all) without real headers - but rather
     * than then blindly trusting m->m_pkthdr.len = send_len regardless,
     * m_length() (a standard, stable BSD mbuf helper that sums the
     * chain's ACTUAL data length, independent of m_copyback()'s own
     * bookkeeping) is used to verify the copy really landed before this
     * packet is trusted and reinjected. If it's short - M_NOWAIT failed
     * to grow the chain under memory pressure, the one failure mode the
     * file header already flags - the packet is dropped instead of
     * reinjected with stale/uninitialized trailing bytes, keeping this
     * path fail-closed like every other rejection in this file rather
     * than fail-open. */
    if (m_length(m, NULL) < send_len)
    {
      m_freem(m);
      free(pend, M_DEVBUF, sizeof(*pend));
      return;
    }
    m->m_pkthdr.len = (int)send_len;
    otpfw_mark_reinjected(m);

    if (pend->direction == OTP_FW_PKT_OUTBOUND)
    {
      if (pend->family == AF_INET6)
        ip6_output(m, NULL, NULL, 0, NULL, NULL);
      else
        ip_output(m, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
      m->m_pkthdr.ph_ifidx = pend->rcvif_index;
      if (pend->family == AF_INET6)
        ip6_input(m);
      else
        ip_input(m);
    }
  }

  free(pend, M_DEVBUF, sizeof(*pend));
}

/* ------------------------------------------------------------------ */
/* Character device: /dev/otpfw - modeled directly on bpf.c's open/      */
/* close/read/write/ioctl shape (see the file header).                  */
/* ------------------------------------------------------------------ */

void
otpfwattach(int num)
{
  (void)num;
  otpfw_candidates = mallocarray(OTP_FW_WIRE_MAX_CANDIDATES, sizeof(otp_fw_candidate_t), M_DEVBUF, M_WAITOK | M_ZERO);
}

int
otpfwopen(dev_t dev, int flag, int mode, struct proc *p)
{
  (void)dev;
  (void)flag;
  (void)mode;
  /* Only root should be able to see candidate packets or push verdicts
   * - a compromised reader could trivially turn this into a total
   * network blackhole or, worse, a plaintext-injection oracle. */
  if (suser(p) != 0)
    return EPERM;

  mtx_enter(&otpfw_queue_lock);
  if (otpfw_device_is_open)
  {
    mtx_leave(&otpfw_queue_lock);
    return EBUSY; /* single-daemon-instance design - see the file header */
  }
  otpfw_device_is_open = 1;
  otpfw_device_closing = 0; /* a fresh open after a previous close's teardown - clear the flag left over from that */
  mtx_leave(&otpfw_queue_lock);
  return 0;
}

int
otpfwclose(dev_t dev, int flag, int mode, struct proc *p)
{
  (void)dev;
  (void)flag;
  (void)mode;
  (void)p;

  mtx_enter(&otpfw_queue_lock);
  otpfw_device_is_open = 0;
  otpfw_device_closing = 1;
  /* Drain anything still queued - see otpfw_drain_queues_locked()'s own
   * comment for why leaving these for a hypothetical future daemon
   * instance to find would just leak them instead. */
  otpfw_drain_queues_locked();
  wakeup(&otpfw_ready_queue);
  mtx_leave(&otpfw_queue_lock);
  return 0;
}

int
otpfwread(dev_t dev, struct uio *uio, int ioflag)
{
  (void)dev;
  (void)ioflag;
  struct otpfw_pending *pend;

  mtx_enter(&otpfw_queue_lock);
  while (TAILQ_EMPTY(&otpfw_ready_queue) && !otpfw_device_closing)
  {
    int rc = msleep_nsec(&otpfw_ready_queue, &otpfw_queue_lock, PZERO | PCATCH, "otpfwrd", INFSLP);
    if (rc != 0)
    {
      mtx_leave(&otpfw_queue_lock);
      return rc; /* interrupted (e.g. Ctrl-C on the daemon) */
    }
  }
  if (otpfw_device_closing)
  {
    mtx_leave(&otpfw_queue_lock);
    return ENXIO;
  }
  pend = TAILQ_FIRST(&otpfw_ready_queue);
  TAILQ_REMOVE(&otpfw_ready_queue, pend, pend_ready_link);
  mtx_leave(&otpfw_queue_lock);

  static otp_fw_dequeued_packet_t out; /* too large for a kernel stack frame - safe as a single shared static only because /dev/otpfw enforces single-open, see the file header */
  memset(&out, 0, sizeof(out));
  out.packet_id = pend->packet_id;
  out.direction = (uint32_t)pend->direction;
  out.data_len = pend->data_len;
  memcpy(out.data, pend->data, pend->data_len);

  return uiomove(&out, sizeof(out), uio);
}

int
otpfwwrite(dev_t dev, struct uio *uio, int ioflag)
{
  (void)dev;
  (void)ioflag;
  static otp_fw_verdict_submission_t in; /* too large for a kernel stack frame - see otpfwread()'s identical note */

  if (uio->uio_resid != sizeof(in))
    return EINVAL;

  int error = uiomove(&in, sizeof(in), uio);
  if (error)
    return error;

  otpfw_apply_verdict(&in);
  return 0;
}

int
otpfwioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
  (void)dev;
  (void)flag;
  (void)p;

  switch (cmd)
  {
  case OTP_FW_IOC_SET_ENABLED:
  {
    uint32_t v = *(uint32_t *)data;
    mtx_enter(&otpfw_enabled_lock);
    otpfw_enabled = (v != 0);
    mtx_leave(&otpfw_enabled_lock);
    return 0;
  }
  case OTP_FW_IOC_GET_ENABLED:
    mtx_enter(&otpfw_enabled_lock);
    *(uint32_t *)data = (uint32_t)otpfw_enabled;
    mtx_leave(&otpfw_enabled_lock);
    return 0;
  case OTP_FW_IOC_SET_CANDIDATES:
  {
    otp_fw_set_candidates_t *req = (otp_fw_set_candidates_t *)data;
    if (req->count > OTP_FW_WIRE_MAX_CANDIDATES)
      return EINVAL;
    otp_fw_candidate_t *buf = mallocarray(req->count, sizeof(otp_fw_candidate_t), M_DEVBUF, M_WAITOK);
    int error = copyin(req->candidates, buf, req->count * sizeof(otp_fw_candidate_t));
    if (error)
    {
      free(buf, M_DEVBUF, req->count * sizeof(otp_fw_candidate_t));
      return error;
    }
    error = otpfw_set_candidates(buf, req->count);
    free(buf, M_DEVBUF, req->count * sizeof(otp_fw_candidate_t));
    return error;
  }
  default:
    return ENOTTY;
  }
}
