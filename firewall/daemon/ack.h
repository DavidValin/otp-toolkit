#ifndef OTP_FW_ACK_H
#define OTP_FW_ACK_H

#include "common.h"
#include "config.h" /* FwConfig, for ack_recover_outstanding() */
#include "keychain.h" /* MAX_NAME_LENGTH */

#include <time.h>

/* Delivery-acknowledgment tracking: closes the gap left by
 * keychain_set_assume_delivered(1) (required for a non-interactive
 * daemon - src/cipher.h - since there's no terminal to answer the
 * library's own "was the previous message delivered?" confirmation
 * prompt). Per that prompt's own comment in src/cipher.c: "[the
 * metadata layer] cannot restore a channel that has already
 * desynchronized" - once a message is silently dropped by a peer
 * firewall (out-of-order arrival, network loss, anything), the two
 * sides' key offsets are permanently out of sync for that
 * contact+direction, because OTP key material can only ever move
 * forward. TCP's own retransmission does NOT reliably fix this: a
 * retransmission is a brand new outbound packet that gets encrypted
 * fresh at whatever offset the sender has since reached, not the offset
 * the receiver is still stuck expecting.
 *
 * This module makes assume_delivered's assumption actually true instead
 * of blind, using the library's own existing delivery-reference
 * primitive (src/cipher.h's --with-ack-file / cipher_set_ack_file()):
 * after a successful decrypt, the receiving firewall sends the
 * message's source_id back to the sender over a small UDP side channel
 * (OTP_FW_ACK_PORT) - safe to send in the clear, per cipher.h's own
 * documentation of that value ("disclosing it afterwards reveals
 * nothing that protected the plaintext"). The sending firewall gates
 * ALL new encryption to a contact behind having seen that ack for the
 * previous message: this makes each contact effectively stop-and-wait
 * (one message in flight at a time), the direct cost of actually
 * closing the desync gap rather than assuming it away - see
 * ../README.md's "Delivery acknowledgment" section for the full
 * tradeoff discussion.
 *
 * Not thread-safe, same reasoning as pin.h: the daemon runs a single
 * processing loop. */

/* Big enough for the worst realistic case (IPv6 header 40 + TCP header
 * with options up to 60) with headroom; UDP's 8-byte header fits with
 * room to spare. Only the header portion is kept here - NOT the
 * ciphertext payload, which would make this table far too large to
 * keep in memory (see the file header's sizing note) and is unnecessary
 * anyway: src/cipher.c's own keep_last_copy() mechanism already keeps
 * the exact ciphertext durably on disk, byte-identical, retrievable via
 * keychain_recover_last() whenever a retry actually needs it. */
#define OTP_FW_ACK_HEADER_CAP 128

typedef struct
{
  char contact[MAX_NAME_LENGTH];
  int in_use;
  int outstanding; /* true: sent a message, no matching ack seen yet */
  int has_expected_source_id; /* false for a slot recovered at startup (see ack_mark_outstanding()) whose real source_id could not be recovered - such a slot can never be cleared by an incoming ack (fails closed) until an operator resolves it out of band */
  unsigned char expected_source_id[OTP_FW_ACK_SOURCE_ID_LEN];
  size_t seq; /* the message's EncryptedSequence - needed to build/discard its ack-ref filename (see ack_read_source_id_file()/ack_discard_source_id_file()) */
  time_t sent_at; /* last time (original send or retry) this slot's ciphertext went out - drives the retry timeout */
  int family;     /* AF_INET or AF_INET6 */
  char dest_ip[OTP_FW_IPSTR_LEN];
  unsigned char header[OTP_FW_ACK_HEADER_CAP]; /* the original packet's IP+L4 header bytes (everything before the L4 payload), verbatim */
  int header_len; /* 0 means no header is available - see ack_mark_outstanding()'s note on startup-recovered slots; such a slot can never be auto-retried, only naturally acked or manually resolved */
} AckSlot;

typedef struct
{
  AckSlot slots[OTP_FW_MAX_ACK_SLOTS];
  int count;
} AckTable;

void ack_table_init(AckTable *t);

/* Egress gate: may `contact` encrypt and send a NEW message right now?
 * 1 = yes (no message outstanding for this contact, or none tracked
 * yet). 0 = no, a previous message is still awaiting its ack - the
 * caller must not call otp_fw_encrypt_packet() for this contact and
 * should instead reject the packet (OTP_FW_ACK_PENDING), the same
 * "drop and let TCP retry later" posture the rest of this project uses
 * for every other transient rejection reason. */
int ack_egress_allowed(const AckTable *t, const char *contact);

/* Records that `contact` now has an outstanding ack pending. Upserts
 * (creates the slot if this is the first message tracked for this
 * contact). `seq` is the message's EncryptedSequence.
 *
 * `source_id` may be NULL (recovered-at-startup case - see
 * ack_recover_outstanding() below and the file header's note on why the
 * ack-ref file might not have survived): the
 * slot is still marked outstanding (still correctly blocks new egress
 * to this contact), but has_expected_source_id is left false, so
 * ack_clear_if_matching() can never clear it until an operator resolves
 * it out of band - failing closed rather than either silently allowing
 * new traffic or accepting an unverified ack.
 *
 * `header`/`header_len` is the original packet's IP+L4 header bytes
 * (NOT the payload) - kept so a later timeout retry can reconstruct the
 * exact original packet by concatenating this header with the
 * ciphertext re-fetched from keychain_recover_last() (see
 * ack_scan_timeouts()). `header` may be NULL / header_len may be 0 (the
 * same recovered-at-startup case: the original packet's headers are
 * never persisted anywhere, so a crash-recovered slot cannot be
 * auto-retried - ack_scan_timeouts()'s caller must check
 * slot->header_len before attempting a redeliver).
 *
 * Returns 0 on success, -1 if the table is full (see
 * OTP_FW_MAX_ACK_SLOTS) or header_len is negative or exceeds
 * OTP_FW_ACK_HEADER_CAP. */
int ack_mark_outstanding(AckTable *t, const char *contact, size_t seq,
                         const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN],
                         const char *dest_ip, int family,
                         const unsigned char *header, int header_len);

/* Clears the outstanding flag for `contact` if `source_id` matches what
 * was recorded for it (always false for a slot with no known expected
 * source_id - see ack_mark_outstanding()). On a match, also discards
 * that message's ack-ref file (see ack_discard_source_id_file()) - it's
 * now genuinely confirmed, so the durable "still outstanding" signal it
 * provided is no longer needed. Returns 1 if it matched and cleared
 * something, 0 otherwise - a stale, unknown, or mismatched ack is
 * simply ignored, never treated as an error: an attacker gains nothing
 * by sending garbage or replayed source_ids here (see the file header),
 * so there is nothing to defend against beyond not acting on it. */
int ack_clear_if_matching(AckTable *t, const char *contact,
                          const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN]);

/* Removes a contact's slot entirely - used on contact removal or a
 * firewall.config change, same spirit as pin_clear_contact(). */
void ack_clear_contact(AckTable *t, const char *contact);

/* Callback invoked once per outstanding slot older than the timeout
 * during ack_scan_timeouts(), with read-only access to the whole slot
 * (its header bytes are what the caller needs to reconstruct the
 * packet). The caller is expected to actually resend it (fetching the
 * matching ciphertext via keychain_recover_last(contact, 1, ...) and
 * concatenating it after `slot->header` - see main.c) and, on a
 * successful resend, call ack_touch_retry() to reset this slot's clock
 * - ack_scan_timeouts() only identifies candidates, it never touches
 * sent_at itself, so a resend that fails to actually go out doesn't
 * falsely reset the timer. */
typedef void (*AckRetryFn)(const AckSlot *slot, void *user_data);
void ack_scan_timeouts(const AckTable *t, int timeout_seconds, AckRetryFn retry_cb, void *user_data);

/* Resets a slot's clock after a successful retry-resend (see above). */
void ack_touch_retry(AckTable *t, const char *contact);

/* ---- Wire-level protocol on OTP_FW_ACK_PORT -----------------------------
 * Two packet types share this one port, both deliberately minimal and
 * unauthenticated beyond what they inherently prove (see the file
 * header for why that's sufficient):
 *
 * ACK - a 4-byte magic tag plus the 16-byte source_id, sent as a UDP
 * datagram's entire payload. Proves the sender holds the mirror key at
 * that exact offset; nothing more is needed.
 *
 * REDELIVER - sent by a sender whose previous message has gone
 * unacknowledged past the retry timeout (see ack_scan_timeouts()). This
 * is the SAME mechanism on every platform this project supports,
 * deliberately: rather than re-transmitting the original packet onto
 * the real network (which would need a platform-specific way to stop
 * this daemon's own kernel/driver layer from mistaking its own retry
 * for fresh plaintext and re-encrypting it - SO_MARK on Linux, nothing
 * equivalent on macOS's NEPacketTunnelProvider or Windows' WFP), the
 * retry travels over this same already-exempt port instead. Because
 * OTP_FW_ACK_PORT is excluded from the encrypt/decrypt pipeline
 * identically everywhere (the same shape as each platform's existing
 * ICMPv6 exemption - see otp_firewall.c/OTPFirewallBridge.c/
 * otp_firewall_driver.c's own port checks), a REDELIVER packet
 * automatically bypasses re-encryption with no extra platform-specific
 * logic required at all. The receiver reconstructs the original packet
 * (stored header + the carried ciphertext) and feeds it through the
 * exact same otp_fw_decrypt_packet() path a normal candidate packet
 * would use - from its perspective this is indistinguishable from the
 * original packet having simply arrived late. */

#define OTP_FW_ACK_MAGIC_ACK "OFWA"
#define OTP_FW_ACK_MAGIC_REDELIVER "OFWR"
#define OTP_FW_ACK_WIRE_LEN (4 + OTP_FW_ACK_SOURCE_ID_LEN) /* fixed size of an ACK packet */

/* Generous enough for the worst-case reconstructed packet (header +
 * OTP_FW_ACK_HEADER_CAP-bounded, ciphertext up to a full IPv6 jumbo-free
 * payload plus OTP growth) - large UDP datagrams like this rely on
 * ordinary IP fragmentation to reach the peer, the same accepted,
 * already-documented v1 tradeoff every other oversized OTP-wrapped
 * packet in this project relies on. */
#define OTP_FW_ACK_MAX_REDELIVER 70000

typedef enum
{
  OTP_FW_ACK_PKT_NONE = 0,      /* nothing read, or not a recognized packet - always safe to ignore */
  OTP_FW_ACK_PKT_ACK = 1,
  OTP_FW_ACK_PKT_REDELIVER = 2
} AckPacketType;

typedef struct
{
  AckPacketType type;
  unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN]; /* meaningful for OTP_FW_ACK_PKT_ACK */
  unsigned char reconstructed[OTP_FW_ACK_MAX_REDELIVER]; /* meaningful for OTP_FW_ACK_PKT_REDELIVER: header+ciphertext concatenated, ready to hand straight to otp_fw_decrypt_packet() exactly like a normal ingress packet */
  int reconstructed_len;
} AckRecvResult;

/* Opens and binds a UDP socket on OTP_FW_ACK_PORT for the given family
 * (AF_INET or AF_INET6), non-blocking. Returns the fd, or -1 on error
 * (check errno). */
int ack_socket_open(int family);

/* Sends one ACK packet for `source_id` to dest_ip:OTP_FW_ACK_PORT.
 * Returns 0 on success, -1 on error. */
int ack_socket_send(const char *dest_ip, int family,
                    const unsigned char source_id[OTP_FW_ACK_SOURCE_ID_LEN]);

/* Sends one REDELIVER packet: `header`/`header_len` (from the AckSlot)
 * followed by `ciphertext`/`ciphertext_len` (freshly fetched by the
 * caller via keychain_recover_last(contact, 1, ...) - see
 * ack_scan_timeouts()). Returns 0 on success, -1 on error (including
 * the combined size exceeding OTP_FW_ACK_MAX_REDELIVER). */
int ack_socket_send_redeliver(const char *dest_ip, int family,
                              const unsigned char *header, int header_len,
                              const unsigned char *ciphertext, int ciphertext_len);

/* Non-blocking read of one packet from `fd` (call only after
 * select()/poll() indicates readability, or accept the EAGAIN cost of
 * polling - ack_socket_open() already sets O_NONBLOCK). Returns 1 with
 * `*out` filled (check out->type) on a well-formed ACK or REDELIVER
 * packet, 0 if nothing was there or the packet was malformed (wrong
 * magic/length - silently ignored, not logged as an error:
 * unauthenticated UDP on this port will occasionally see random
 * noise/scans), -1 on a real socket error. */
int ack_socket_recv(int fd, AckRecvResult *out);

/* Reads the source_id src/cipher.c wrote via cipher_set_ack_file(1) for
 * message `seq` in the given direction, from the current working
 * directory (main.c chdir()s to ~/.otp at startup, per
 * otp_fw_setup_keychain_dir(), so this is always relative to the same
 * place cipher.c itself wrote it - see cipher.h's --with-ack-file
 * documentation for the exact filename convention this matches).
 *
 * Deliberately does NOT delete the file (unlike earlier versions of
 * this function): as long as it's still on disk, it - together with
 * src/cipher.c's own kept-ciphertext file (see keychain_recover_last())
 * - is exactly the durable state that lets a freshly (re)started daemon
 * tell whether a contact's last-sent message is still genuinely
 * unconfirmed, and recover the value needed to recognize its ack when
 * one arrives. Only ack_discard_source_id_file() removes it, once that
 * confirmation has actually happened. Returns 0 on success, -1 if the
 * file is missing, malformed, or unreadable. */
int ack_read_source_id_file(const char *contact, size_t seq, int is_encrypt,
                            unsigned char out[OTP_FW_ACK_SOURCE_ID_LEN]);

/* Removes the ack-ref file ack_read_source_id_file() reads, once its
 * message is genuinely confirmed (an ack was received - see
 * ack_clear_if_matching(), which calls this automatically) or an
 * operator has otherwise resolved it. Piling these up forever would
 * leak disk space for no benefit once a message is no longer
 * outstanding. Safe to call on a file that's already gone (e.g. never
 * existed, or was already discarded) - a missing file is not an error
 * here.
 *
 * Also durably records, in a small per-contact (NOT per-message) marker
 * file, that this contact's message at `seq` is now confirmed - see
 * ack_recover_outstanding()'s use of it below. Unlike the per-message
 * ack-ref file, this marker is overwritten in place each time, so it
 * never accumulates one file per message. */
void ack_discard_source_id_file(const char *contact, size_t seq, int is_encrypt);

/* Startup-recovery orchestration - the fix for the gap an in-memory-only
 * AckTable would otherwise have: without this, a daemon crash/restart
 * while a message was genuinely outstanding would silently lose all
 * tracking of that fact, reopening the exact desync window this whole
 * module exists to close (see the file header). Call this once at
 * startup, after load_keychain() and after `cfg` has been loaded/
 * resolved, but before the ack sockets start processing any real
 * traffic (retries or new egress).
 *
 * For every contact in the global keychain (g_keychain - see
 * src/keychain.h), asks src/cipher.c's own durable "kept copy" mechanism
 * - keychain_recover_last(contact, 1, ...) - whether a sent message has
 * not yet been superseded by a later encrypt call for that contact (that
 * call itself only returns something when confirm_previous_delivery()
 * has NOT yet run for this contact). This alone is NOT the same as
 * "still outstanding": a real ack may already have fully confirmed the
 * message, with cipher.c's own kept copy simply lingering until this
 * contact's next send (which may not happen for a long time) - see
 * ack_discard_source_id_file()'s confirmed-marker above, which is what
 * lets this function tell the two apart. Getting this wrong in the
 * other direction would be a real availability bug, not a rare edge
 * case: without the marker, EVERY restart after a contact's last
 * message was successfully delivered would falsely re-block that
 * contact.
 *
 * The actual decision per contact, in order:
 *   1. keychain_recover_last() says nothing is outstanding
 *      (KEYCHAIN_RECOVER_NO_COPY) - leave the contact alone, the common
 *      case.
 *   2. Otherwise, if the confirmed-marker covers this seq (a real ack
 *      already confirmed it, before or after this run last exited) -
 *      leave the contact alone: it only looks outstanding because
 *      cipher.c hasn't superseded its kept copy yet, which is harmless.
 *   3. Otherwise, mark the slot outstanding in `t`:
 *      - the real source_id, via ack_read_source_id_file(), when that
 *        ack-ref file also survived (the common genuinely-outstanding
 *        case - it's no longer deleted on read, see above) - such a
 *        slot can be cleared by a genuine incoming ack exactly as if
 *        the daemon had never restarted;
 *      - NULL otherwise (the ack-ref file did not survive, AND no
 *        confirmed-marker proves this message safe) - fails closed
 *        (blocks new egress, can never be cleared by any incoming ack)
 *        until an operator resolves it out of band, rather than either
 *        guessing or silently allowing new traffic.
 * `header`/`header_len` are always passed as NULL/0 here: the original
 * packet's IP+L4 header is never persisted anywhere, so a startup-
 * recovered slot can never be auto-retried via ack_scan_timeouts() -
 * only naturally acked, or manually resolved - see ack_mark_outstanding().
 * dest_ip/family are looked up in `cfg` by contact name; a contact with
 * no matching entry is still marked outstanding with dest_ip "" (egress
 * stays correctly blocked regardless of whether a destination is known).
 *
 * A contact with nothing outstanding (keychain_recover_last() returns
 * KEYCHAIN_RECOVER_NO_COPY) is left untouched - the common, non-crash
 * case. Errors from an individual contact's recovery are logged to
 * stderr and otherwise skipped; this must never abort startup over one
 * contact's state. */
void ack_recover_outstanding(AckTable *t, const FwConfig *cfg);

#endif /* OTP_FW_ACK_H */
