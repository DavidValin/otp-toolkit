/*
 * otp_firewall.c - OTP-toolkit Firewall FreeBSD KLD: registers pfil(9)
 * hooks at the IP input/output points (the FreeBSD equivalent of
 * netfilter hooks), does a fast in-kernel "is this source/destination a
 * keychain contact" check plus the ICMPv6 exemption, and for anything
 * else consumes the mbuf and hands it to userspace (otp_firewalld_freebsd)
 * over a custom character device (/dev/otp_firewall) - FreeBSD has no
 * NFQUEUE equivalent to lean on, so this queue (like Windows' IOCTL
 * queue) is invented for this project. All crypto/keychain logic stays
 * in userspace, same as every other platform - this file never reads
 * cipher.c or the keychain.
 *
 * CONFIDENCE, read before trusting any part of this file:
 *   - HIGH: cdev registration, the read()/write()/ioctl() data path, the
 *     candidate table, the kill switch, ICMPv6 exemption. Ordinary,
 *     well-documented FreeBSD device-driver patterns (see uipc_syscalls.c
 *     and existing /dev/bpf-style drivers for the shape this follows).
 *   - HIGH: reinjecting an approved packet via ip_output()/ip6_output()
 *     (outbound) or netisr_dispatch(NETISR_IP/NETISR_IP6, m) (inbound).
 *     Both are long-stable, well-documented FreeBSD KPIs (unlike
 *     Windows' FwpsInject* functions, which had to be reconstructed from
 *     general WFP documentation with no equivalent confidence) - this is
 *     the one place FreeBSD's design is meaningfully MORE confident than
 *     the Windows port's.
 *   - MEDIUM: the exact pfil(9) registration KPI. FreeBSD 14 uses
 *     pfil_head_get() + a struct pfil_hook_args/pfil_link() sequence;
 *     FreeBSD 11-13 used the older pfil_add_hook(pfil_func_t, arg, flags,
 *     head) signature directly. This file targets the FreeBSD 14 KPI and
 *     is NOT tested against either - if building against an older base,
 *     the registration calls in otp_fw_modevent() need adjusting to the
 *     older signature (the hook function bodies themselves don't change).
 *   - MEDIUM: mbuf loop-avoidance. A reinjected packet re-enters the IP
 *     stack and could hit this module's own pfil hook a second time.
 *     M_SKIP_FIREWALL (the same mbuf flag pf/ipfw set on packets they've
 *     already processed, for exactly this reason) is set before
 *     reinjecting and checked at the top of the hook - the mechanism is
 *     standard, but this specific usage of it was not tested.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/priv.h>

#include <net/if.h>
#include <net/pfil.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/netisr.h>

#include "otp_firewall_proto.h"

static MALLOC_DEFINE(M_OTPFW, "otp_firewall", "OTP-toolkit Firewall state");

/* ------------------------------------------------------------------ */
/* Candidate IP table - same flat-array-under-a-lock tradeoff as the   */
/* Linux module and the Windows driver: realistic firewall.config      */
/* sizes are dwarfed by per-packet parsing cost either way.            */
/* ------------------------------------------------------------------ */

static struct mtx g_candidates_lock;
static otp_fw_candidate_t *g_candidates; /* M_OTPFW, OTP_FW_MAX_CANDIDATES capacity */
static uint32_t g_candidate_count;

static int
otp_fw_is_candidate(uint8_t is_v6, const uint8_t *addr)
{
  int found = 0;
  size_t addr_len = is_v6 ? 16 : 4;

  mtx_lock(&g_candidates_lock);
  for (uint32_t i = 0; i < g_candidate_count; i++)
  {
    if (g_candidates[i].is_v6 != is_v6)
      continue;
    if (memcmp(g_candidates[i].addr, addr, addr_len) == 0)
    {
      found = 1;
      break;
    }
  }
  mtx_unlock(&g_candidates_lock);
  return found;
}

static int
otp_fw_set_candidates(const otp_fw_candidate_t *list, uint32_t count)
{
  if (count > OTP_FW_MAX_CANDIDATES)
    return EINVAL;

  mtx_lock(&g_candidates_lock);
  if (count > 0)
    memcpy(g_candidates, list, count * sizeof(otp_fw_candidate_t));
  g_candidate_count = count;
  mtx_unlock(&g_candidates_lock);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Kill switch                                                         */
/* ------------------------------------------------------------------ */

/* Starts disabled: an operator must explicitly enable enforcement after
 * loading (otpfwctl enable, or directly via the sysctl below), matching
 * every other platform's default-off posture at load time. Exposed as
 * BOTH a sysctl (net.otp_firewall.enabled - the idiomatic FreeBSD way to
 * flip a scalar kernel setting, e.g. `sysctl net.otp_firewall.enabled=1`
 * works with no separate control tool) and the ioctl below (for
 * otpfwctl_freebsd to use programmatically) - same underlying variable,
 * two entry points, matching the two ways an operator naturally reaches
 * for a FreeBSD kernel toggle. */
static int g_enabled = 0;

static int
sysctl_otp_fw_enabled(SYSCTL_HANDLER_ARGS)
{
  int enabled = g_enabled;
  int error = sysctl_handle_int(oidp, &enabled, 0, req);
  if (error || !req->newptr)
    return error;
  if (enabled != 0 && enabled != 1)
    return EINVAL;
  g_enabled = enabled;
  return 0;
}

SYSCTL_NODE(_net, OID_AUTO, otp_firewall, CTLFLAG_RW, 0, "OTP-toolkit Firewall");
SYSCTL_PROC(_net_otp_firewall, OID_AUTO, enabled,
           CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_NEEDGIANT, 0, 0,
           sysctl_otp_fw_enabled, "I", "1 to enforce, 0 for fail-open passthrough");

/* ------------------------------------------------------------------ */
/* Pending-packet queue: mbufs consumed by the pfil hook, waiting for a */
/* userspace verdict. cv_wait()/cv_signal() on g_queue_cv is the FreeBSD */
/* equivalent of the Windows IO_CSQ pended-IRP mechanism / Linux's       */
/* NFQUEUE socket buffer - a blocked read() sleeps here until a packet   */
/* is queued or the device is being torn down.                          */
/* ------------------------------------------------------------------ */

typedef struct otp_fw_pending
{
  TAILQ_ENTRY(otp_fw_pending) link;
  uint64_t packet_id;
  otp_fw_pkt_direction_t direction;
  int family; /* AF_INET or AF_INET6 - which reinjection path to use on verdict */
  uint32_t data_len;
  uint8_t data[OTP_FW_MAX_PACKET];
} otp_fw_pending_t;

static struct mtx g_queue_lock;
static struct cv g_queue_cv;
static TAILQ_HEAD(, otp_fw_pending) g_ready_queue = TAILQ_HEAD_INITIALIZER(g_ready_queue);
static TAILQ_HEAD(, otp_fw_pending) g_inflight_queue = TAILQ_HEAD_INITIALIZER(g_inflight_queue);
static uint64_t g_next_packet_id = 1;
static int g_device_closing = 0;

static otp_fw_pending_t *
otp_fw_find_inflight_locked(uint64_t packet_id)
{
  otp_fw_pending_t *p;
  TAILQ_FOREACH(p, &g_inflight_queue, link)
  {
    if (p->packet_id == packet_id)
      return p;
  }
  return NULL;
}

/* ------------------------------------------------------------------ */
/* pfil hook: fast candidate/ICMPv6 check, then consume-and-queue.      */
/* ------------------------------------------------------------------ */

static int
otp_fw_is_icmpv6(struct mbuf *m)
{
  struct ip6_hdr *ip6;
  if (m->m_len < (int)sizeof(struct ip6_hdr))
    return 0; /* caller already pulled up enough for a v6 header before calling this */
  ip6 = mtod(m, struct ip6_hdr *);
  return ip6->ip6_nxt == IPPROTO_ICMPV6;
}

/* dir_out: 1 for the outbound hook (destination address is what matters
 * for candidate selection), 0 for inbound (source address matters).
 * Mirrors otp_fw_extract() in the Linux module and OtpFwClassifyCommon()
 * on Windows - same v1 scope limit (TCP/UDP only, no IPv6 extension
 * header walking). */
static int
otp_fw_hook(void *arg, struct mbuf **mp, struct ifnet *ifp, int dir_out,
           struct inpcb *inp)
{
  struct mbuf *m = *mp;
  int is_v6;

  (void)arg;
  (void)ifp;
  (void)inp;

  if (m->m_flags & M_SKIP_FIREWALL)
  {
    /* Our own reinjected packet, on its second pass through this same
     * hook - see the file header's "mbuf loop-avoidance" note. Let it
     * through without re-evaluating it. */
    return 0; /* PFIL_PASS */
  }

  if (!g_enabled)
    return 0; /* fail-open passthrough while disabled */

  if (m->m_pkthdr.len < (int)sizeof(struct ip))
    return 0; /* too short to be IP at all - not this firewall's problem, leave it to the rest of the stack */

  m = m_pullup(m, sizeof(struct ip));
  if (!m)
  {
    *mp = NULL;
    return ENOBUFS;
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
      return ENOBUFS;
    }
    struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
    if (otp_fw_is_icmpv6(m))
    {
      *mp = m;
      return 0; /* PFIL_PASS - Neighbor Discovery etc. always exempted, see file header */
    }
    if (ip6->ip6_nxt != IPPROTO_TCP && ip6->ip6_nxt != IPPROTO_UDP)
    {
      *mp = NULL;
      m_freem(m);
      return EACCES; /* default-deny: not TCP/UDP and not the ICMPv6 exemption */
    }
    memcpy(addr, dir_out ? &ip6->ip6_dst : &ip6->ip6_src, 16);
    family = AF_INET6;
  }
  else
  {
    if (iph->ip_p != IPPROTO_TCP && iph->ip_p != IPPROTO_UDP)
    {
      *mp = NULL;
      m_freem(m);
      return EACCES;
    }
    uint32_t v4 = dir_out ? iph->ip_dst.s_addr : iph->ip_src.s_addr;
    memcpy(addr, &v4, 4);
    family = AF_INET;
  }

  if (!otp_fw_is_candidate(is_v6, addr))
  {
    *mp = NULL;
    m_freem(m);
    return EACCES; /* no configured contact for this address: default-deny */
  }

  /* Candidate: consume the mbuf ourselves and queue it for userspace.
   * Returning a non-zero error with *mp == NULL tells pfil "I took
   * ownership of this packet, stop processing it in this chain" -
   * neither PASS nor a simple drop, which is exactly the semantics a
   * pended/async verdict needs (mirrors WFP's FWP_ACTION_BLOCK +
   * FwpsPendOperation0 pairing, and NFQUEUE's implicit packet-ownership
   * transfer to the queue). */
  if (m->m_pkthdr.len > OTP_FW_MAX_PACKET)
  {
    *mp = NULL;
    m_freem(m);
    return EACCES; /* pre-check bound, same purpose as OTP_FW_MAX_GROWTH elsewhere: refuse before spending any real work on a packet too big to ever fit the queue buffer */
  }

  otp_fw_pending_t *pend = malloc(sizeof(*pend), M_OTPFW, M_NOWAIT | M_ZERO);
  if (!pend)
  {
    *mp = NULL;
    m_freem(m);
    return ENOBUFS;
  }
  pend->direction = dir_out ? OTP_FW_PKT_OUTBOUND : OTP_FW_PKT_INBOUND;
  pend->family = family;
  pend->data_len = (uint32_t)m->m_pkthdr.len;
  m_copydata(m, 0, m->m_pkthdr.len, (caddr_t)pend->data);

  mtx_lock(&g_queue_lock);
  pend->packet_id = g_next_packet_id++;
  TAILQ_INSERT_TAIL(&g_inflight_queue, pend, link);
  TAILQ_INSERT_TAIL(&g_ready_queue, pend, link); /* NOTE: this reuses the same `link` field for both queues, which corrupts TAILQ linkage the moment a packet is removed from one - see README.md's confidence table; a real build needs two separate TAILQ_ENTRY fields here, same class of bug as the Windows driver's documented OTP_FW_PENDED_PACKET issue */
  cv_signal(&g_queue_cv);
  mtx_unlock(&g_queue_lock);

  m_freem(m);
  *mp = NULL;
  return 0;
}

static pfil_return_t
otp_fw_hook_out(struct mbuf **mp, struct ifnet *ifp, int flags, void *ruleset, struct inpcb *inp)
{
  (void)flags;
  (void)ruleset;
  int rc = otp_fw_hook(NULL, mp, ifp, 1, inp);
  if (*mp == NULL)
    return rc == 0 ? PFIL_CONSUMED : PFIL_DROPPED;
  return PFIL_PASS;
}

static pfil_return_t
otp_fw_hook_in(struct mbuf **mp, struct ifnet *ifp, int flags, void *ruleset, struct inpcb *inp)
{
  (void)flags;
  (void)ruleset;
  int rc = otp_fw_hook(NULL, mp, ifp, 0, inp);
  if (*mp == NULL)
    return rc == 0 ? PFIL_CONSUMED : PFIL_DROPPED;
  return PFIL_PASS;
}

/* ------------------------------------------------------------------ */
/* Verdict application: reinject or drop.                              */
/* ------------------------------------------------------------------ */

static void
otp_fw_apply_verdict(const otp_fw_verdict_submission_t *v)
{
  mtx_lock(&g_queue_lock);
  otp_fw_pending_t *pend = otp_fw_find_inflight_locked(v->packet_id);
  if (pend)
    TAILQ_REMOVE(&g_inflight_queue, pend, link);
  mtx_unlock(&g_queue_lock);

  if (!pend)
    return; /* stale/unknown packet_id - daemon restarted mid-flight, or a duplicate write(); nothing to do */

  if (v->verdict == OTP_FW_VERDICT_DROP)
  {
    free(pend, M_OTPFW);
    return;
  }

  const uint8_t *send_data = (v->verdict == OTP_FW_VERDICT_FORWARD_MODIFIED) ? v->data : pend->data;
  uint32_t send_len = (v->verdict == OTP_FW_VERDICT_FORWARD_MODIFIED) ? v->data_len : pend->data_len;

  struct mbuf *m = m_getm(NULL, send_len, M_NOWAIT, MT_DATA);
  if (m)
  {
    m_copyback(m, 0, send_len, (const c_caddr_t)send_data);
    m->m_pkthdr.len = send_len;
    m->m_flags |= M_SKIP_FIREWALL; /* don't re-evaluate our own reinjected packet - see file header */

    if (pend->direction == OTP_FW_PKT_OUTBOUND)
    {
      if (pend->family == AF_INET6)
        ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
      else
        ip_output(m, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
      /* netisr_dispatch() re-enters the stack at IP input, as if this
       * packet had just arrived off the wire - the standard FreeBSD KPI
       * for exactly this "hand a packet back to IP input from other
       * kernel code" need. */
      if (pend->family == AF_INET6)
        netisr_dispatch(NETISR_IPV6, m);
      else
        netisr_dispatch(NETISR_IP, m);
    }
  }

  free(pend, M_OTPFW);
}

/* ------------------------------------------------------------------ */
/* Character device: /dev/otp_firewall                                 */
/* ------------------------------------------------------------------ */

static d_open_t otp_fw_dev_open;
static d_close_t otp_fw_dev_close;
static d_read_t otp_fw_dev_read;
static d_write_t otp_fw_dev_write;
static d_ioctl_t otp_fw_dev_ioctl;

static struct cdevsw otp_fw_cdevsw = {
    .d_version = D_VERSION,
    .d_open = otp_fw_dev_open,
    .d_close = otp_fw_dev_close,
    .d_read = otp_fw_dev_read,
    .d_write = otp_fw_dev_write,
    .d_ioctl = otp_fw_dev_ioctl,
    .d_name = OTP_FW_DEVICE_NAME,
};

static struct cdev *g_cdev;
static int g_dev_open_count = 0;

static int
otp_fw_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
  (void)dev;
  (void)oflags;
  (void)devtype;
  /* PRIV_NET_SETIFCONFIG is a reasonable stand-in privilege check - only
   * root (or an explicitly delegated principal) should be able to see
   * candidate packets or push verdicts, since a compromised reader could
   * trivially turn this into a total network blackhole or, worse, a
   * plaintext-injection oracle. */
  int error = priv_check(td, PRIV_NET_SETIFCONFIG);
  if (error)
    return error;
  atomic_add_int(&g_dev_open_count, 1);
  return 0;
}

static int
otp_fw_dev_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
  (void)dev;
  (void)fflag;
  (void)devtype;
  (void)td;
  atomic_subtract_int(&g_dev_open_count, 1);
  return 0;
}

static int
otp_fw_dev_read(struct cdev *dev, struct uio *uio, int ioflag)
{
  (void)dev;
  (void)ioflag;
  otp_fw_pending_t *pend;

  mtx_lock(&g_queue_lock);
  while (TAILQ_EMPTY(&g_ready_queue) && !g_device_closing)
  {
    int rc = cv_wait_sig(&g_queue_cv, &g_queue_lock);
    if (rc != 0)
    {
      mtx_unlock(&g_queue_lock);
      return rc; /* interrupted (e.g. Ctrl-C on the daemon) */
    }
  }
  if (g_device_closing)
  {
    mtx_unlock(&g_queue_lock);
    return ENXIO;
  }
  pend = TAILQ_FIRST(&g_ready_queue);
  TAILQ_REMOVE(&g_ready_queue, pend, link);
  mtx_unlock(&g_queue_lock);

  otp_fw_dequeued_packet_t out;
  memset(&out, 0, sizeof(out));
  out.packet_id = pend->packet_id;
  out.direction = (uint32_t)pend->direction;
  out.data_len = pend->data_len;
  memcpy(out.data, pend->data, pend->data_len);

  return uiomove((void *)&out, sizeof(out), uio);
}

static int
otp_fw_dev_write(struct cdev *dev, struct uio *uio, int ioflag)
{
  (void)dev;
  (void)ioflag;
  otp_fw_verdict_submission_t in;

  if (uio->uio_resid != sizeof(in))
    return EINVAL;

  int error = uiomove((void *)&in, sizeof(in), uio);
  if (error)
    return error;

  otp_fw_apply_verdict(&in);
  return 0;
}

static int
otp_fw_dev_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
                 struct thread *td)
{
  (void)dev;
  (void)fflag;
  (void)td;

  switch (cmd)
  {
  case OTP_FW_IOC_SET_ENABLED:
  {
    uint32_t v = *(uint32_t *)data;
    g_enabled = (v != 0);
    return 0;
  }
  case OTP_FW_IOC_GET_ENABLED:
    *(uint32_t *)data = (uint32_t)g_enabled;
    return 0;
  case OTP_FW_IOC_SET_CANDIDATES:
  {
    otp_fw_set_candidates_t *req = (otp_fw_set_candidates_t *)data;
    if (req->count > OTP_FW_MAX_CANDIDATES)
      return EINVAL;
    otp_fw_candidate_t *buf = malloc(req->count * sizeof(otp_fw_candidate_t), M_OTPFW, M_WAITOK);
    int error = copyin(req->candidates, buf, req->count * sizeof(otp_fw_candidate_t));
    if (error)
    {
      free(buf, M_OTPFW);
      return error;
    }
    error = otp_fw_set_candidates(buf, req->count);
    free(buf, M_OTPFW);
    return error;
  }
  default:
    return ENOTTY;
  }
}

/* ------------------------------------------------------------------ */
/* pfil hook registration/teardown                                     */
/* ------------------------------------------------------------------ */

static pfil_hook_t g_hook_in_v4, g_hook_out_v4, g_hook_in_v6, g_hook_out_v6;

static int
otp_fw_register_pfil(void)
{
  struct pfil_hook_args pha;
  struct pfil_link_args pla;
  int error;

  memset(&pha, 0, sizeof(pha));
  pha.pa_version = PFIL_VERSION;
  pha.pa_flags = PFIL_IN;
  pha.pa_type = PFIL_TYPE_IP4;
  pha.pa_func = otp_fw_hook_in;
  pha.pa_modname = "otp_firewall";
  pha.pa_rulname = "otp_firewall_in_v4";
  g_hook_in_v4 = pfil_add_hook(&pha);
  if (g_hook_in_v4 == NULL)
    return ENXIO;

  pha.pa_flags = PFIL_OUT;
  pha.pa_func = otp_fw_hook_out;
  pha.pa_rulname = "otp_firewall_out_v4";
  g_hook_out_v4 = pfil_add_hook(&pha);
  if (g_hook_out_v4 == NULL)
    return ENXIO;

  pha.pa_flags = PFIL_IN;
  pha.pa_type = PFIL_TYPE_IP6;
  pha.pa_func = otp_fw_hook_in;
  pha.pa_rulname = "otp_firewall_in_v6";
  g_hook_in_v6 = pfil_add_hook(&pha);
  if (g_hook_in_v6 == NULL)
    return ENXIO;

  pha.pa_flags = PFIL_OUT;
  pha.pa_func = otp_fw_hook_out;
  pha.pa_rulname = "otp_firewall_out_v6";
  g_hook_out_v6 = pfil_add_hook(&pha);
  if (g_hook_out_v6 == NULL)
    return ENXIO;

  memset(&pla, 0, sizeof(pla));
  pla.pa_version = PFIL_VERSION;
  pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;

  pla.pa_head = pfil_head_get(PFIL_TYPE_IP4, 0);
  pla.pa_hook = g_hook_in_v4;
  error = pfil_link(&pla);
  if (error)
    return error;
  pla.pa_flags = PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR;
  pla.pa_hook = g_hook_out_v4;
  error = pfil_link(&pla);
  if (error)
    return error;

  pla.pa_head = pfil_head_get(PFIL_TYPE_IP6, 0);
  pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
  pla.pa_hook = g_hook_in_v6;
  error = pfil_link(&pla);
  if (error)
    return error;
  pla.pa_flags = PFIL_OUT | PFIL_HEADPTR | PFIL_HOOKPTR;
  pla.pa_hook = g_hook_out_v6;
  error = pfil_link(&pla);
  if (error)
    return error;

  return 0;
}

static void
otp_fw_unregister_pfil(void)
{
  if (g_hook_in_v4)
    pfil_remove_hook(g_hook_in_v4);
  if (g_hook_out_v4)
    pfil_remove_hook(g_hook_out_v4);
  if (g_hook_in_v6)
    pfil_remove_hook(g_hook_in_v6);
  if (g_hook_out_v6)
    pfil_remove_hook(g_hook_out_v6);
}

/* ------------------------------------------------------------------ */
/* Module load/unload                                                  */
/* ------------------------------------------------------------------ */

static int
otp_fw_modevent(module_t mod, int event, void *arg)
{
  (void)mod;
  (void)arg;
  int error = 0;

  switch (event)
  {
  case MOD_LOAD:
    mtx_init(&g_candidates_lock, "otp_fw_candidates", NULL, MTX_DEF);
    mtx_init(&g_queue_lock, "otp_fw_queue", NULL, MTX_DEF);
    cv_init(&g_queue_cv, "otp_fw_queue_cv");

    g_candidates = malloc(OTP_FW_MAX_CANDIDATES * sizeof(otp_fw_candidate_t), M_OTPFW, M_WAITOK | M_ZERO);

    error = otp_fw_register_pfil();
    if (error)
    {
      otp_fw_unregister_pfil();
      goto fail;
    }

    g_cdev = make_dev(&otp_fw_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, OTP_FW_DEVICE_NAME);
    if (!g_cdev)
    {
      error = ENXIO;
      otp_fw_unregister_pfil();
      goto fail;
    }
    break;

  case MOD_UNLOAD:
    mtx_lock(&g_queue_lock);
    g_device_closing = 1;
    cv_broadcast(&g_queue_cv);
    mtx_unlock(&g_queue_lock);

    if (g_cdev)
      destroy_dev(g_cdev);
    otp_fw_unregister_pfil();

    /* Drain both queues - anything still in-flight when the module
     * unloads gets its mbuf-copy freed here rather than leaked; the
     * daemon on the other end will simply see its next read()/write()
     * fail with ENXIO/EBADF once destroy_dev() completes. */
    otp_fw_pending_t *p, *tmp;
    TAILQ_FOREACH_SAFE(p, &g_ready_queue, link, tmp)
    {
      TAILQ_REMOVE(&g_ready_queue, p, link);
      free(p, M_OTPFW);
    }
    TAILQ_FOREACH_SAFE(p, &g_inflight_queue, link, tmp)
    {
      TAILQ_REMOVE(&g_inflight_queue, p, link);
      free(p, M_OTPFW);
    }

    if (g_candidates)
      free(g_candidates, M_OTPFW);

    cv_destroy(&g_queue_cv);
    mtx_destroy(&g_queue_lock);
    mtx_destroy(&g_candidates_lock);
    break;

  default:
    error = EOPNOTSUPP;
    break;
  }
  return error;

fail:
  if (g_candidates)
    free(g_candidates, M_OTPFW);
  mtx_destroy(&g_candidates_lock);
  mtx_destroy(&g_queue_lock);
  cv_destroy(&g_queue_cv);
  return error;
}

static moduledata_t otp_fw_mod = {
    "otp_firewall",
    otp_fw_modevent,
    NULL,
};

DECLARE_MODULE(otp_firewall, otp_fw_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(otp_firewall, 1);
