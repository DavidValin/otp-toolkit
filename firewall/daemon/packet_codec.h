#ifndef OTP_FW_PACKET_CODEC_H
#define OTP_FW_PACKET_CODEC_H

#include "common.h"
#include "config.h"
#include "trial.h"

#include <stddef.h>

/* How many bytes an OTP-wrapped payload can grow by relative to the
 * original: one source_id chunk (META_SOURCE_LEN, 16 bytes in cipher.c)
 * plus the encrypted metadata pad. 64 bytes is a generous upper bound
 * (see the "Per-message metadata layer" comment in cipher.c) with room
 * to spare; the codec still range-checks against the caller's actual
 * output buffer rather than trusting this constant. */
#define OTP_FW_MAX_GROWTH 128

/* Egress: `pkt` is the original captured IP packet (network byte order,
 * as handed up by NFQUEUE) of a TCP or UDP flow. On OTP_FW_OK, `out`
 * holds the modified packet (same source/dest IP and port, grown
 * payload, fixed lengths and checksums) and `*out_len` its length;
 * `contact_out` receives the contact name used. `out_cap` must be at
 * least `pkt_len` + OTP_FW_MAX_GROWTH. */
otp_fw_result_t otp_fw_encrypt_packet(const char *keychain_dir, const FwConfig *cfg,
                                      const unsigned char *pkt, int pkt_len,
                                      unsigned char *out, int out_cap, int *out_len,
                                      char *contact_out, size_t contact_out_size);

/* Ingress: `pkt` is the (possibly grown) ciphertext packet as received.
 * `candidates` is the ordered list to try (see trial.h). On OTP_FW_OK,
 * `out`/`*out_len` hold the packet shrunk back to its original plaintext
 * form and `contact_out` receives the contact that validated it (the
 * caller pins src_ip -> that contact). `out_cap` only needs to be at
 * least `pkt_len` since decrypting never grows a packet. */
otp_fw_result_t otp_fw_decrypt_packet(const char *keychain_dir, const CandidateList *candidates,
                                      const unsigned char *pkt, int pkt_len,
                                      unsigned char *out, int out_cap, int *out_len,
                                      char *contact_out, size_t contact_out_size);

/* --mode=log-only classification: reports what otp_fw_encrypt_packet()/
 * otp_fw_decrypt_packet() would decide, WITHOUT ever calling
 * encrypt_with_contact()/decrypt_with_contact() - so unlike the real
 * calls above, these never spend key material. This matters because a
 * genuine successful encrypt/decrypt is not reversible: it permanently
 * consumes one-time-pad key bytes, which log-only mode must not do to
 * traffic it's only supposed to be observing. See the "Rollout mode"
 * section of docs/FIREWALL.md.
 *
 * otp_fw_classify_egress() can determine a full OTP_FW_OK/otherwise
 * verdict for free (contact selection is deterministic from
 * firewall.config, not conditional on running the cipher). Encrypting
 * that plaintext for output is what needs the real call.
 *
 * otp_fw_classify_ingress() cannot: whether an inbound packet validates
 * is only knowable by actually decrypting it, so this never returns
 * OTP_FW_OK. It returns OTP_FW_NO_CONTACT/OTP_FW_PIN_MISMATCH when there
 * is no candidate at all (free to determine), otherwise
 * OTP_FW_NOT_EVALUATED with the top candidate's name as a hint. */
otp_fw_result_t otp_fw_classify_egress(const char *keychain_dir, const FwConfig *cfg,
                                       const unsigned char *pkt, int pkt_len,
                                       char *contact_out, size_t contact_out_size);
otp_fw_result_t otp_fw_classify_ingress(const CandidateList *candidates,
                                        char *contact_out, size_t contact_out_size);

/* Parses just enough of `pkt` to report addresses/ports for logging,
 * regardless of whether encrypt/decrypt was attempted. Returns 0 if the
 * packet could be parsed as IPv4/IPv6 TCP/UDP, -1 otherwise (fields left
 * as empty strings / 0). */
int otp_fw_describe_packet(const unsigned char *pkt, int pkt_len,
                           char *src_ip, size_t src_ip_size, unsigned *src_port,
                           char *dst_ip, size_t dst_ip_size, unsigned *dst_port,
                           const char **proto_name);

#endif /* OTP_FW_PACKET_CODEC_H */
