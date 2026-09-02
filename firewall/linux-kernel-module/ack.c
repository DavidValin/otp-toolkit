#include "ack.h"

#include "cipher.h" /* keychain_recover_last(), KEYCHAIN_RECOVER_NO_COPY */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Socket headers - same portability split as checksum.h/config.c: this
 * file is kept byte-identical across every platform's own copy (Linux,
 * macOS, Windows, FreeBSD), same as pin.c/config.c/checksum.c. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

void ack_table_init(AckTable *t)
{
  memset(t, 0, sizeof(*t));
}

static AckSlot *find_slot(AckTable *t, const char *contact)
{
  for (int i = 0; i < t->count; i++)
  {
    if (t->slots[i].in_use && strcmp(t->slots[i].contact, contact) == 0)
      return &t->slots[i];
  }
  return NULL;
}

int ack_egress_allowed(const AckTable *t, const char *contact)
{
  for (int i = 0; i < t->count; i++)
  {
    if (t->slots[i].in_use && strcmp(t->slots[i].contact, contact) == 0)
      return !t->slots[i].outstanding;
  }
  return 1; /* no slot yet: nothing has ever been sent to this contact, so nothing to wait on */
}

int ack_mark_outstanding(AckTable *t, const char *contact, size_t seq,
                         const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN],
                         const char *dest_ip, int family,
                         const unsigned char *header, int header_len)
{
  if (header_len < 0 || header_len > OTP_FW_ACK_HEADER_CAP)
    return -1;

  AckSlot *slot = find_slot(t, contact);
  if (!slot)
  {
    if (t->count >= OTP_FW_MAX_ACK_SLOTS)
      return -1;
    slot = &t->slots[t->count++];
    memset(slot, 0, sizeof(*slot));
    snprintf(slot->contact, sizeof(slot->contact), "%s", contact);
    slot->in_use = 1;
  }
  slot->outstanding = 1;
  slot->seq = seq;
  if (source_id)
  {
    slot->has_expected_source_id = 1;
    memcpy(slot->expected_source_id, source_id, OTP_FW_ACK_SOURCE_ID_LEN);
  }
  else
  {
    /* Recovered at startup without a usable ack-ref file - see this
     * function's own doc comment in ack.h. Deliberately left unset
     * (has_expected_source_id stays 0) rather than zero-filled and
     * treated as a real value: ack_clear_if_matching() must never
     * accept anything for this slot until an operator resolves it. */
    slot->has_expected_source_id = 0;
  }
  slot->sent_at = time(NULL);
  slot->family = family;
  snprintf(slot->dest_ip, sizeof(slot->dest_ip), "%s", dest_ip ? dest_ip : "");
  if (header && header_len > 0)
    memcpy(slot->header, header, (size_t)header_len);
  slot->header_len = header ? header_len : 0;
  return 0;
}

int ack_clear_if_matching(AckTable *t, const char *contact,
                          const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN])
{
  AckSlot *slot = find_slot(t, contact);
  if (!slot || !slot->outstanding || !slot->has_expected_source_id)
    return 0;
  if (memcmp(slot->expected_source_id, source_id, OTP_FW_ACK_SOURCE_ID_LEN) != 0)
    return 0;
  slot->outstanding = 0;
  ack_discard_source_id_file(contact, slot->seq, 1);
  return 1;
}

void ack_clear_contact(AckTable *t, const char *contact)
{
  for (int i = 0; i < t->count; i++)
  {
    if (t->slots[i].in_use && strcmp(t->slots[i].contact, contact) == 0)
    {
      /* Swap-remove, same pattern as pin_clear_ip(): overwrite this slot
       * with the last one and shrink count, rather than leaving a
       * tombstoned hole find_slot() would have to skip forever. */
      t->slots[i] = t->slots[t->count - 1];
      t->count--;
      return;
    }
  }
}

void ack_scan_timeouts(const AckTable *t, int timeout_seconds, AckRetryFn retry_cb, void *user_data)
{
  time_t now = time(NULL);
  for (int i = 0; i < t->count; i++)
  {
    const AckSlot *slot = &t->slots[i];
    if (slot->in_use && slot->outstanding && (now - slot->sent_at) >= timeout_seconds)
      retry_cb(slot, user_data);
  }
}

void ack_touch_retry(AckTable *t, const char *contact)
{
  AckSlot *slot = find_slot(t, contact);
  if (slot)
    slot->sent_at = time(NULL);
}

int ack_socket_open(int family)
{
  /* This header's whole API uses a plain `int` fd uniformly across
   * every platform this project supports, matching POSIX - but
   * WinSock's socket() returns SOCKET (UINT_PTR, 64-bit-wide on x64),
   * not int. The narrowing cast below is deliberate, not an oversight:
   * INVALID_SOCKET's all-ones bit pattern narrows to -1 either way (so
   * the `< 0` failure check below still works correctly), and real
   * Windows socket handles are allocated as small values in practice,
   * even though the API makes no formal guarantee of that. Accepted as
   * a known, narrow portability wart rather than giving this one
   * platform's fd type special treatment throughout the rest of this
   * file. */
#ifdef _WIN32
  int fd = (int)socket(family, SOCK_DGRAM, 0);
#else
  int fd = socket(family, SOCK_DGRAM, 0);
#endif
  if (fd < 0)
    return -1;

  if (family == AF_INET)
  {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(OTP_FW_ACK_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
#ifdef _WIN32
      closesocket(fd);
#else
      close(fd);
#endif
      return -1;
    }
  }
  else
  {
    /* Without this, an IPv6 wildcard bind is dual-stack by default on
     * many systems (net.ipv6.bindv6only=0 is the common Linux default)
     * and tries to also claim the IPv4 address space on this port -
     * colliding with the separately-opened AF_INET socket above and
     * failing with EADDRINUSE every time, silently breaking IPv6
     * delivery-ack tracking on exactly the systems this matters most
     * for. Setting IPV6_V6ONLY makes this socket handle only genuine
     * IPv6 traffic, leaving the IPv4 socket to own that address family
     * independently, as intended. */
    int v6only = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(OTP_FW_ACK_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
#ifdef _WIN32
      closesocket(fd);
#else
      close(fd);
#endif
      return -1;
    }
  }

#ifdef _WIN32
  u_long nonblock = 1;
  ioctlsocket(fd, FIONBIO, &nonblock);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

  return fd;
}

static int close_fd(int fd)
{
#ifdef _WIN32
  return closesocket(fd);
#else
  return close(fd);
#endif
}

/* Shared by ack_socket_send()/ack_socket_send_redeliver(): opens a
 * throwaway socket, sends exactly one datagram to dest_ip:OTP_FW_ACK_PORT,
 * closes it. A fresh per-call socket (rather than reusing the bound
 * listening socket to send from) keeps this side free of the listening
 * socket's own state and matches how infrequently sends happen here
 * (once per message, or once per retry) - not a path worth optimizing
 * for socket reuse. */
static int send_datagram(const char *dest_ip, int family, const void *buf, size_t len)
{
  /* Deliberate SOCKET->int narrowing on Windows - see ack_socket_open()'s
   * comment. */
#ifdef _WIN32
  int fd = (int)socket(family, SOCK_DGRAM, 0);
#else
  int fd = socket(family, SOCK_DGRAM, 0);
#endif
  if (fd < 0)
    return -1;

  int rc;
  if (family == AF_INET)
  {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(OTP_FW_ACK_PORT);
    if (inet_pton(AF_INET, dest_ip, &addr.sin_addr) != 1)
    {
      close_fd(fd);
      return -1;
    }
    rc = (int)sendto(fd, (const char *)buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
  }
  else
  {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(OTP_FW_ACK_PORT);
    if (inet_pton(AF_INET6, dest_ip, &addr.sin6_addr) != 1)
    {
      close_fd(fd);
      return -1;
    }
    rc = (int)sendto(fd, (const char *)buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
  }

  close_fd(fd);
  return rc == (int)len ? 0 : -1;
}

int ack_socket_send(const char *dest_ip, int family,
                    const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN])
{
  unsigned char buf[OTP_FW_ACK_WIRE_LEN];
  memcpy(buf, OTP_FW_ACK_MAGIC_ACK, 4);
  memcpy(buf + 4, source_id, OTP_FW_ACK_SOURCE_ID_LEN);
  return send_datagram(dest_ip, family, buf, sizeof(buf));
}

int ack_socket_send_redeliver(const char *dest_ip, int family,
                              const unsigned char *header, int header_len,
                              const unsigned char *ciphertext, int ciphertext_len)
{
  if (header_len < 0 || ciphertext_len < 0)
    return -1;

  /* Wire layout: magic(4) + header_len(2, network order) + header +
   * ciphertext_len(4, network order) + ciphertext. */
  size_t total = 4 + 2 + (size_t)header_len + 4 + (size_t)ciphertext_len;
  if (total > OTP_FW_ACK_MAX_REDELIVER)
    return -1;

  unsigned char *buf = malloc(total);
  if (!buf)
    return -1;

  size_t pos = 0;
  memcpy(buf + pos, OTP_FW_ACK_MAGIC_REDELIVER, 4);
  pos += 4;
  uint16_t hlen_be = htons((uint16_t)header_len);
  memcpy(buf + pos, &hlen_be, 2);
  pos += 2;
  memcpy(buf + pos, header, (size_t)header_len);
  pos += (size_t)header_len;
  uint32_t clen_be = htonl((uint32_t)ciphertext_len);
  memcpy(buf + pos, &clen_be, 4);
  pos += 4;
  memcpy(buf + pos, ciphertext, (size_t)ciphertext_len);
  pos += (size_t)ciphertext_len;

  int rc = send_datagram(dest_ip, family, buf, pos);
  free(buf);
  return rc;
}

int ack_socket_recv(int fd, AckRecvResult *out)
{
  static unsigned char buf[OTP_FW_ACK_MAX_REDELIVER + 1]; /* +1: detect an oversized datagram rather than silently truncating it; static since this is only ever called from the single-threaded main loop and is far too large for a stack local */
  memset(out, 0, sizeof(*out));

  int n = (int)recv(fd, (char *)buf, sizeof(buf), 0);
  if (n < 0)
  {
#ifdef _WIN32
    return (WSAGetLastError() == WSAEWOULDBLOCK) ? 0 : -1;
#else
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
#endif
  }

  if (n == OTP_FW_ACK_WIRE_LEN && memcmp(buf, OTP_FW_ACK_MAGIC_ACK, 4) == 0)
  {
    out->type = OTP_FW_ACK_PKT_ACK;
    memcpy(out->source_id, buf + 4, OTP_FW_ACK_SOURCE_ID_LEN);
    return 1;
  }

  if (n >= 10 /* magic(4) + header_len(2) + ciphertext_len(4), minimum possible REDELIVER frame */ &&
     memcmp(buf, OTP_FW_ACK_MAGIC_REDELIVER, 4) == 0)
  {
    uint16_t hlen_be;
    memcpy(&hlen_be, buf + 4, 2);
    int header_len = ntohs(hlen_be);

    if (6 + header_len + 4 > n)
      return 0; /* truncated/malformed - ignored, see the header's note */

    uint32_t clen_be;
    memcpy(&clen_be, buf + 6 + header_len, 4);
    int ciphertext_len = (int)ntohl(clen_be);

    if (ciphertext_len < 0 || 6 + header_len + 4 + ciphertext_len != n)
      return 0; /* malformed length fields - ignored */
    if (header_len + ciphertext_len > (int)sizeof(out->reconstructed))
      return 0; /* larger than anything a real message could produce - ignored */

    memcpy(out->reconstructed, buf + 6, (size_t)header_len);
    memcpy(out->reconstructed + header_len, buf + 6 + header_len + 4, (size_t)ciphertext_len);
    out->reconstructed_len = header_len + ciphertext_len;
    out->type = OTP_FW_ACK_PKT_REDELIVER;
    return 1;
  }

  return 0; /* not one of ours - silently ignored, see the header's note on why that's safe */
}

/* Shared by ack_read_source_id_file()/ack_discard_source_id_file() - the
 * one place that spells out this naming convention, matching
 * cipher.h's --with-ack-file documentation exactly. */
static void ack_ref_file_path(const char *contact, size_t seq, int is_encrypt,
                              char *out, size_t out_size)
{
  snprintf(out, out_size, "%s_%zu_%s", contact, seq,
          is_encrypt ? "ack_ref.sent.txt" : "ack.received.txt");
}

int ack_read_source_id_file(const char *contact, size_t seq, int is_encrypt,
                            unsigned char out[OTP_FW_ACK_SOURCE_ID_LEN])
{
  char path[700];
  ack_ref_file_path(contact, seq, is_encrypt, path, sizeof(path));

  FILE *f = fopen(path, "r");
  if (!f)
    return -1;

  /* 32 lowercase hex characters + a trailing newline, per cipher.h's
   * --with-ack-file documentation - sized with one byte of headroom so
   * a malformed/oversized file is detected (fread() reading fewer bytes
   * than expected) rather than silently truncated and misparsed. */
  char hex[2 * OTP_FW_ACK_SOURCE_ID_LEN + 2] = {0};
  size_t n = fread(hex, 1, sizeof(hex) - 1, f);
  fclose(f);
  if (n < 2 * OTP_FW_ACK_SOURCE_ID_LEN)
    return -1;

  for (size_t i = 0; i < OTP_FW_ACK_SOURCE_ID_LEN; i++)
  {
    unsigned int byte;
    if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
      return -1;
    out[i] = (unsigned char)byte;
  }

  return 0;
}

/* Per-contact (NOT per-message, unlike the ack-ref file) marker recording
 * the highest EncryptedSequence known to be genuinely confirmed - see
 * ack_recover_outstanding()'s use of ack_confirmed_marker_covers() for
 * why this exists: src/cipher.c's own kept "last sent" copy
 * (keychain_recover_last()) is only discarded when the NEXT
 * encrypt_with_contact() call for that contact runs (its own internal
 * confirm-on-next-send bookkeeping, unrelated to whether a real ack was
 * ever seen), which may not happen again for a long time even after a
 * real ack has fully confirmed the current message. Without this marker,
 * a restart in that gap would have no way to tell "confirmed via a real
 * ack, kept copy just hasn't been superseded yet" (harmless) apart from
 * "the ack-ref file itself failed to survive the crash while the
 * message really is still unconfirmed" (must fail closed) - both look
 * identical as "kept copy present, ack-ref file absent" otherwise.
 * Overwritten in place each time, so - unlike the per-message ack-ref
 * file - this never accumulates one file per message. */
static void ack_confirmed_marker_path(const char *contact, char *out, size_t out_size)
{
  snprintf(out, out_size, "%s_last_confirmed_ack.txt", contact);
}

static void ack_write_confirmed_marker(const char *contact, size_t seq)
{
  char path[700];
  ack_confirmed_marker_path(contact, path, sizeof(path));
  FILE *f = fopen(path, "w");
  if (!f)
    return; /* best-effort: see ack_recover_outstanding()'s conservative (fail-closed) fallback for when this is missing */
  fprintf(f, "%zu\n", seq);
  fclose(f);
}

/* True if `contact`'s confirmed-marker records a seq >= `seq` - i.e.
 * this exact message (or a later one) is already known, durably, to
 * have been genuinely acknowledged. False (not just "unknown") on a
 * missing/unreadable/stale marker - see ack_recover_outstanding(),
 * which treats false as "cannot prove this is safe" and fails closed. */
static int ack_confirmed_marker_covers(const char *contact, size_t seq)
{
  char path[700];
  ack_confirmed_marker_path(contact, path, sizeof(path));
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  size_t marked_seq = 0;
  int ok = (fscanf(f, "%zu", &marked_seq) == 1);
  fclose(f);
  return ok && marked_seq >= seq;
}

void ack_discard_source_id_file(const char *contact, size_t seq, int is_encrypt)
{
  char path[700];
  ack_ref_file_path(contact, seq, is_encrypt, path, sizeof(path));
  remove(path); /* ENOENT (already gone) is not an error here - see ack.h */

  /* Only a real confirmed egress ack reaches here (see
   * ack_clear_if_matching(), the sole caller of this function with
   * is_encrypt=1 - AckTable only ever tracks sent messages) - record it
   * durably so a later restart can tell this apart from a genuinely
   * still-outstanding message. */
  if (is_encrypt)
    ack_write_confirmed_marker(contact, seq);
}

/* dest_ip/family lookup helper for ack_recover_outstanding() below - a
 * contact absent from `cfg` (or unresolved) yields "" / AF_INET, which
 * is fine: the slot still correctly blocks new egress either way, it
 * just won't have a destination to auto-retry toward (moot anyway,
 * since header_len is always 0 for a recovered slot - see ack.h). */
static void ack_lookup_dest(const FwConfig *cfg, const char *contact,
                            const char **dest_ip, int *family)
{
  *dest_ip = "";
  *family = AF_INET;
  if (!cfg)
    return;

  for (int i = 0; i < cfg->count; i++)
  {
    if (strcmp(cfg->entries[i].contact, contact) == 0 && cfg->entries[i].resolved_ip[0])
    {
      *dest_ip = cfg->entries[i].resolved_ip;
      *family = strchr(*dest_ip, ':') ? AF_INET6 : AF_INET;
      return;
    }
  }
}

void ack_recover_outstanding(AckTable *t, const FwConfig *cfg)
{
  for (int i = 0; i < g_keychain.count; i++)
  {
    Contact *c = &g_keychain.contacts[i];

    char *buf = NULL;
    size_t buflen = 0;
    FILE *outf = open_memstream(&buf, &buflen);
    if (!outf)
    {
      fprintf(stderr, "Warning: ack recovery - could not allocate memstream for '%s'\n", c->Name);
      continue;
    }
    int rc = keychain_recover_last(c->Name, 1, outf);
    fclose(outf);
    free(buf);

    if (rc == KEYCHAIN_RECOVER_NO_COPY)
      continue; /* nothing outstanding for this contact - the common case */
    if (rc != 0)
    {
      fprintf(stderr, "Warning: ack recovery - could not check last-sent copy for '%s'\n", c->Name);
      continue;
    }

    /* rc == 0: cipher.c's own kept copy for this contact hasn't yet been
     * superseded by a later encrypt call. That alone does NOT mean the
     * message is still outstanding - see ack_confirmed_marker_covers()'s
     * doc comment: a real ack may already have fully confirmed it, with
     * the kept copy simply lingering until the contact's next message.
     * Check the durable confirmed-marker first; only fall through to
     * treating this as outstanding if it does NOT prove confirmation. */
    if (ack_confirmed_marker_covers(c->Name, c->EncryptedSequence))
      continue; /* genuinely confirmed via a real ack before the prior run ended - not outstanding */

    unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN];
    int have_source_id = (ack_read_source_id_file(c->Name, c->EncryptedSequence, 1, source_id) == 0);

    const char *dest_ip;
    int family;
    ack_lookup_dest(cfg, c->Name, &dest_ip, &family);

    if (ack_mark_outstanding(t, c->Name, c->EncryptedSequence,
                             have_source_id ? source_id : NULL,
                             dest_ip, family, NULL, 0) != 0)
    {
      fprintf(stderr, "Warning: ack recovery - could not track recovered outstanding message for '%s' (table full)\n", c->Name);
    }
    else
    {
      fprintf(stderr,
             "Notice: recovered an unacknowledged message for '%s' from a prior run - blocking new encryption until %s\n",
             c->Name, have_source_id ? "its ack arrives" : "an operator resolves it (no ack-ref file survived)");
    }
  }
}
