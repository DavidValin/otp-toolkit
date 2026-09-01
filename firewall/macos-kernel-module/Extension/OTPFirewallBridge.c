/*
 * OTPFirewallBridge.c - the macOS analog of firewall/daemon/main.c's
 * egress_cb()/ingress_cb(), minus the NFQUEUE plumbing (there's no
 * separate kernel piece here to hand a verdict back to - this bridge,
 * called from OTPFirewallProvider.swift's packet loop, IS the
 * enforcement point). Reuses firewall/daemon/{common,config,pin,trial,
 * packet_codec,log,keychain_setup}.h and links against the real
 * src/{cipher,keychain,commit}.c unmodified, exactly like the Linux
 * daemon does.
 *
 * UNVERIFIED: written and reviewed by hand, never compiled - see
 * ../README.md. The locking discipline below (a single mutex around
 * every call) is deliberately conservative: unlike the Linux daemon's
 * single NFQUEUE recv loop, this bridge is called from Swift code whose
 * exact threading (does NEPacketTunnelProvider ever deliver reads
 * concurrently? does a config-reload timer run on a different queue
 * than the packet loop?) isn't something this could be confirmed
 * without a real target to test against.
 */

#include "OTPFirewallBridge.h"

#include "common.h"
#include "config.h"
#include "keychain_setup.h"
#include "log.h"
#include "packet_codec.h"
#include "pin.h"
#include "trial.h"

#include "keychain.h"
#include "cipher.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static FwConfig g_cfg;
static PinTable g_pins;
static char g_keychain_dir[512];
static int g_setup_done = 0;

static void reconcile_pins_with_config_locked(void)
{
  for (int i = 0; i < g_pins.count; i++)
  {
    char ip[OTP_FW_IPSTR_LEN];
    snprintf(ip, sizeof(ip), "%s", g_pins.entries[i].ip);
    const char *configured = fwconfig_contact_for_ip(&g_cfg, ip);
    if (configured && strcmp(configured, g_pins.entries[i].contact) != 0)
    {
      pin_clear_ip(&g_pins, ip);
      i--;
    }
  }
}

int otp_fw_bridge_setup(void)
{
  pthread_mutex_lock(&g_lock);

  fwconfig_init(&g_cfg);
  pin_init(&g_pins);

  int rc = otp_fw_setup_keychain_dir();
  if (rc == 0)
    rc = get_keychain_dir(g_keychain_dir, sizeof(g_keychain_dir));
  if (rc == 0)
    rc = load_keychain();
  if (rc == 0)
  {
    /* Required: encrypt/decrypt_with_contact() otherwise block on an
     * interactive "did the previous message arrive?" confirmation
     * prompt (cipher.h) that this extension, with no terminal, can
     * never answer. */
    keychain_set_assume_delivered(1);
    rc = otp_fw_log_init();
  }
  if (rc == 0)
  {
    fwconfig_load(OTP_FW_CONFIG_NAME, &g_cfg); /* relative to ~/.otp, per otp_fw_setup_keychain_dir()'s chdir */
    fwconfig_resolve(&g_cfg);
    g_setup_done = 1;
  }

  pthread_mutex_unlock(&g_lock);
  return rc;
}

void otp_fw_bridge_reload_config(void)
{
  pthread_mutex_lock(&g_lock);
  if (g_setup_done)
  {
    fwconfig_load(OTP_FW_CONFIG_NAME, &g_cfg);
    fwconfig_resolve(&g_cfg);
    reconcile_pins_with_config_locked();
  }
  pthread_mutex_unlock(&g_lock);
}

/* No lock needed: pure read-only inspection of the caller's own buffer,
 * touches none of the shared state the mutex protects. */
int otp_fw_bridge_is_icmpv6(const uint8_t *pkt, int pkt_len)
{
  if (pkt_len < (int)sizeof(struct ip6_hdr))
    return 0;
  int version = (pkt[0] >> 4) & 0x0F;
  if (version != 6)
    return 0;
  const struct ip6_hdr *ip6h = (const struct ip6_hdr *)pkt;
  return ip6h->ip6_nxt == IPPROTO_ICMPV6;
}

otp_fw_action_t otp_fw_bridge_process_outbound(const uint8_t *pkt, int pkt_len,
                                               uint8_t *out_buf, int out_cap, int *out_len,
                                               int enforce_mode)
{
  if (!g_setup_done)
    return OTP_FW_ACTION_DROP;

  pthread_mutex_lock(&g_lock);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;
  if (!enforce_mode)
    r = otp_fw_classify_egress(g_keychain_dir, &g_cfg, pkt, pkt_len, contact, sizeof(contact));
  else
    r = otp_fw_encrypt_packet(g_keychain_dir, &g_cfg, pkt, pkt_len, out_buf, out_cap, out_len,
                              contact, sizeof(contact));

  otp_fw_action_t action;
  if (r == OTP_FW_OK)
  {
    otp_fw_log_authorized("egress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    action = enforce_mode ? OTP_FW_ACTION_FORWARD_MODIFIED : OTP_FW_ACTION_FORWARD_ORIGINAL;
  }
  else
  {
    otp_fw_log_restricted("egress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
    action = !enforce_mode ? OTP_FW_ACTION_FORWARD_ORIGINAL : OTP_FW_ACTION_DROP;
  }

  pthread_mutex_unlock(&g_lock);
  return action;
}

otp_fw_action_t otp_fw_bridge_process_inbound(const uint8_t *pkt, int pkt_len,
                                              uint8_t *out_buf, int out_cap, int *out_len,
                                              int enforce_mode)
{
  if (!g_setup_done)
    return OTP_FW_ACTION_DROP;

  pthread_mutex_lock(&g_lock);

  char src_ip[OTP_FW_IPSTR_LEN], dst_ip[OTP_FW_IPSTR_LEN];
  unsigned src_port, dst_port;
  const char *proto;
  otp_fw_describe_packet(pkt, pkt_len, src_ip, sizeof(src_ip), &src_port,
                         dst_ip, sizeof(dst_ip), &dst_port, &proto);

  /* static: CandidateList is ~2.5MB (OTP_FW_MAX_CANDIDATES *
   * MAX_NAME_LENGTH) - see the identical comment in firewall/daemon/
   * main.c for why this must not be a stack local. */
  static CandidateList candidates;
  trial_select_primary(g_keychain_dir, &g_cfg, &g_pins, src_ip, &candidates);

  char contact[MAX_NAME_LENGTH] = {0};
  otp_fw_result_t r;
  if (!enforce_mode)
    r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
  else
    r = otp_fw_decrypt_packet(g_keychain_dir, &candidates, pkt, pkt_len, out_buf, out_cap, out_len,
                              contact, sizeof(contact));

  int primary_failed = !enforce_mode ? (r == OTP_FW_NO_CONTACT) : (r != OTP_FW_OK);
  if (primary_failed && !candidates.exclusive)
  {
    trial_add_fallback_scan(g_keychain_dir, &candidates);
    if (!enforce_mode)
      r = otp_fw_classify_ingress(&candidates, contact, sizeof(contact));
    else
      r = otp_fw_decrypt_packet(g_keychain_dir, &candidates, pkt, pkt_len, out_buf, out_cap, out_len,
                                contact, sizeof(contact));
  }

  otp_fw_action_t action;
  if (r == OTP_FW_OK)
  {
    if (pin_set(&g_pins, src_ip, contact) != 0)
      fprintf(stderr, "Warning: pin table full (%d entries) - '%s' will use the slower "
                      "trial path on every packet until a pin frees up\n",
             OTP_FW_MAX_PINS, src_ip);
    otp_fw_log_authorized("ingress", contact, src_ip, src_port, dst_ip, dst_port, proto);
    action = enforce_mode ? OTP_FW_ACTION_FORWARD_MODIFIED : OTP_FW_ACTION_FORWARD_ORIGINAL;
  }
  else
  {
    otp_fw_log_restricted("ingress", contact[0] ? contact : NULL, src_ip, src_port, dst_ip, dst_port,
                          proto, otp_fw_result_reason(r));
    action = !enforce_mode ? OTP_FW_ACTION_FORWARD_ORIGINAL : OTP_FW_ACTION_DROP;
  }

  pthread_mutex_unlock(&g_lock);
  return action;
}

/* See the extended caveat above this function's declaration in
 * OTPFirewallBridge.h - this is the least-confident piece of this whole
 * port. IPv4 (SOCK_RAW + IPPROTO_RAW + IP_HDRINCL, a decades-old and
 * well-documented BSD sockets pattern) is the more solid of the two;
 * IPv6's raw-socket header-inclusion story is far less commonly used in
 * practice and this is a best-effort implementation, not a confirmed
 * one. */
int otp_fw_bridge_send_raw(const uint8_t *pkt, int pkt_len, int family)
{
  if (family == 4)
  {
    if (pkt_len < (int)sizeof(struct ip))
    {
      errno = EINVAL;
      return -1;
    }
    const struct ip *iph = (const struct ip *)pkt;

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
      return -1;

    int on = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
    {
      close(fd);
      return -1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_len = sizeof(dst);
    memcpy(&dst.sin_addr, &iph->ip_dst, 4);

    ssize_t n = sendto(fd, pkt, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return (n == (ssize_t)pkt_len) ? 0 : -1;
  }

  if (family == 6)
  {
    if (pkt_len < (int)sizeof(struct ip6_hdr))
    {
      errno = EINVAL;
      return -1;
    }
    const struct ip6_hdr *ip6h = (const struct ip6_hdr *)pkt;

    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0)
      return -1;

#ifdef IPV6_HDRINCL
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &on, sizeof(on)) != 0)
    {
      close(fd);
      return -1;
    }
#endif

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    dst.sin6_len = sizeof(dst);
    dst.sin6_addr = ip6h->ip6_dst;

    ssize_t n = sendto(fd, pkt, (size_t)pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
    close(fd);
    return (n == (ssize_t)pkt_len) ? 0 : -1;
  }

  errno = EAFNOSUPPORT;
  return -1;
}
