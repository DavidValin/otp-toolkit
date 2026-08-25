/*****************************************************************************\
 *                                                                            *
 *   otp-toolkit v1.7.0                                                       *
 *                                                                            *
 *    simple but effective one time pad encryption / decryption command       *
 *    that works with stdin/stdout, managing contacts and key material        *
 *    through a keychain. Supports key pair generation.                       *
 *                                                                            *
 *   Author: David Valin <hola@davidvalin.com> - www.davidvalin.com           *
 *   License: Apache 2.0                                                      *
 *   August 17 2026                                                           *
 *                                                                            *
 \****************************************************************************/

// Enable Large File Support (LFS) for files >2GB on 32-bit POSIX systems
#ifndef _WIN32
#define _FILE_OFFSET_BITS 64
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#ifdef _WIN32
#include <process.h>
#endif

#include "keychain.h"
#include "cipher.h"
#include "compat.h"

/* Streaming chunk for --xor, matching the 4MB chunk encrypt/decrypt use. */
#define XOR_CHUNK_SIZE (4 * 1024 * 1024)

#ifndef _WIN32
#define O_BINARY 0
#endif
#ifdef _WIN32
#include <io.h>
#include <direct.h>
#include <windows.h>
/* Map POSIX flags to MSVC equivalents */
#ifndef O_WRONLY
#define O_WRONLY _O_WRONLY
#endif
#ifndef O_CREAT
#define O_CREAT _O_CREAT
#endif
#ifndef O_EXCL
#define O_EXCL _O_EXCL
#endif
#ifndef O_BINARY
#define O_BINARY _O_BINARY
#endif
/* Map POSIX names to the CRT's underscore spellings. */
#define close _close
#define open _open
#define mkdir(path, mode) _mkdir(path)
#define rmdir _rmdir
#define dup _dup
#define dup2 _dup2
#define fileno _fileno
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

/* Does a standard stream refer to an interactive terminal? stdin: used
 * by --new-key-pair to fail fast instead of blocking on a stdin nobody
 * is feeding. stdout: gates the generation progress spinner and ANSI
 * colors, so redirected or piped output stays plain text. */
#ifdef _WIN32
#define otp_isatty(f) _isatty(_fileno(f))
#else
#define otp_isatty(f) isatty(fileno(f))
#endif
#define otp_stdin_is_tty() otp_isatty(stdin)
#define otp_stdout_is_tty() otp_isatty(stdout)

/* ANSI colors for the key-pair generation report; emitted only when
 * stdout is a terminal. OTP_BLACK_ON_WHITE sets foreground and
 * background together as a palette pair (30 + 47) rather than either
 * one alone or an absolute RGB: terminal themes remap palette colors
 * but keep 30 dark and 47 light, so the pair stays readable in any
 * theme - whereas setting only the background would render the dark
 * themes' near-white default text on a white bar. */
#define OTP_GREEN "\x1b[32m"
#define OTP_YELLOW "\x1b[33m"
#define OTP_RED "\x1b[31m"
#define OTP_BLACK_ON_WHITE "\x1b[30;47m"
#define OTP_RESET "\x1b[0m"

/* --new-key-pair writes four files, two per party, each pair inside its
 * own <name>_keys/ directory; the two pads it draws from stdin are each
 * written to two of the files. Close and remove every file created so
 * far: a half-written set is not usable as a pad, and leaving it behind
 * would also block the retry with EEXIST, since these are created
 * O_EXCL. remove() rather than unlink() - it is standard C and needs no
 * per-platform mapping. */
#define KEYPAIR_FILES 4
#define KEYPAIR_DIRS 2
static void keypair_cleanup(FILE *files[KEYPAIR_FILES], char names[KEYPAIR_FILES][256],
                            char dirs[KEYPAIR_DIRS][256])
{
  for (int i = 0; i < KEYPAIR_FILES; i++)
  {
    if (files[i])
    {
      fclose(files[i]);
      files[i] = NULL;
    }
    if (names[i][0])
      remove(names[i]);
  }
  /* Only directories this run created are recorded in dirs[], so a
   * pre-existing <name>_keys/ the user already had is never deleted.
   * rmdir() also refuses a non-empty directory, so any file we did not
   * create (and therefore did not remove above) keeps its directory. */
  for (int i = 0; i < KEYPAIR_DIRS; i++)
  {
    if (dirs[i][0])
      rmdir(dirs[i]);
  }
}

/* Progress spinner shown while the pads stream from stdin, so a long
 * generation visibly distinguishes "working" from "hung". Active only
 * when the frame index is >= 0 (set by the caller when stdout is a
 * terminal); one tick per streamed chunk, each overwriting the previous
 * frame with a backspace. */
static int keypair_spinner_frame = -1;
static void keypair_spinner_tick(void)
{
  static const char frames[] = "|/-\\";
  if (keypair_spinner_frame < 0)
    return;
  printf("\b%c", frames[keypair_spinner_frame++ & 3]);
  fflush(stdout);
}

/* Stream `size` bytes from stdin into two files at once, one chunk at a
 * time. The pad is never held whole in memory: peak usage is one chunk
 * regardless of key size, so key pairs can be far larger than RAM (the
 * keychain accepts keys up to 1TB). */
#define KEYPAIR_CHUNK (1024 * 1024)
/* Word-wraps help text at OTP_HELP_WIDTH columns so the --help output
 * stays readable in a standard 80-column terminal. The text is
 * processed line by line (splitting on the '\n' already embedded in
 * the help strings, which mark paragraph breaks and list structure);
 * each source line's leading whitespace is preserved as the indent for
 * its own wrapped continuation lines, plus two extra spaces, so a
 * wrapped line reads as a visually indented continuation rather than
 * a new list item flush against the margin. */
#define OTP_HELP_WIDTH 70
/* `color` (an empty string for none) is applied per printed line rather
 * than around the whole block: the escapes are emitted after each
 * line's indent and closed before its newline, so they never enter the
 * width arithmetic below - which counts bytes - and a wrapped colored
 * line cannot leak its color across the newline into the next one. */
static void otp_print_wrapped_colored(const char *text, size_t extra_indent, const char *color)
{
  const char *line = text;
  while (*line)
  {
    const char *nl = strchr(line, '\n');
    size_t linelen = nl ? (size_t)(nl - line) : strlen(line);

    /* src_indent: leading spaces already in this source line, used as
     * the wrap indent so list markers ("  " or "    ") line up with
     * how the string was authored. indent: the printed column the
     * first word starts at, once extra_indent (e.g. past a tab-stop
     * command name) is added in. cont_indent: where a wrapped
     * continuation resumes - two columns deeper, so it reads as a
     * continuation rather than a sibling list item. */
    size_t src_indent = 0;
    while (src_indent < linelen && line[src_indent] == ' ')
      src_indent++;
    size_t indent = extra_indent + src_indent;
    size_t cont_indent = indent + 2;

    size_t pos = src_indent;
    if (pos < linelen)
    {
      for (size_t i = 0; i < indent; i++)
        putchar(' ');
      fputs(color, stdout);
    }
    size_t col = indent;
    int first_word = 1;
    while (pos < linelen)
    {
      size_t wstart = pos;
      while (pos < linelen && line[pos] != ' ')
        pos++;
      size_t wlen = pos - wstart;

      /* first_word is only true right after printing the line's (or a
       * wrapped continuation's) indent, so no leading space is due
       * yet - a word there never needs an extra wrap check. */
      if (!first_word && col + 1 + wlen > OTP_HELP_WIDTH)
      {
        if (*color)
          fputs(OTP_RESET, stdout);
        putchar('\n');
        for (size_t i = 0; i < cont_indent; i++)
          putchar(' ');
        fputs(color, stdout);
        col = cont_indent;
        first_word = 1;
      }
      if (!first_word)
      {
        putchar(' ');
        col++;
      }
      fwrite(line + wstart, 1, wlen, stdout);
      col += wlen;
      first_word = 0;

      while (pos < linelen && line[pos] == ' ')
        pos++;
    }
    if (*color && src_indent < linelen)
      fputs(OTP_RESET, stdout);
    putchar('\n');

    if (!nl)
      break;
    line = nl + 1;
  }
}
static void otp_print_wrapped_indented(const char *text, size_t extra_indent)
{
  otp_print_wrapped_colored(text, extra_indent, "");
}
static void otp_print_wrapped(const char *text)
{
  otp_print_wrapped_colored(text, 0, "");
}

/* --add-contact reports OK/FAIL with the summary/reason recolored yellow
 * or red - but that text is generated deep inside keychain.c's
 * add_contact()/add_contact_with_keys(), which stay presentation-free
 * (plain fprintf/printf, no ANSI) since nothing else calls them. Rather
 * than push color codes into that library layer, the stream is
 * redirected to a temp file for the duration of the call and read back
 * here, so cli.c - which already owns every other color decision - can
 * recolor it before replaying it to the real stream. Returns the FILE*
 * to pass to otp_capture_end(), or NULL if capture could not be set up
 * (the call still runs normally; its output just goes straight to
 * `stream`, uncaptured, same as without this wrapper). */
static FILE *otp_capture_begin(FILE *stream, int *saved_fd_out)
{
  *saved_fd_out = -1;
  fflush(stream);
  int saved_fd = dup(fileno(stream));
  if (saved_fd < 0)
    return NULL;
  FILE *tmp = tmpfile();
  if (!tmp)
  {
    close(saved_fd);
    return NULL;
  }
  if (dup2(fileno(tmp), fileno(stream)) < 0)
  {
    fclose(tmp);
    close(saved_fd);
    return NULL;
  }
  *saved_fd_out = saved_fd;
  return tmp;
}

/* Restores the real stream and reads back whatever the captured call
 * wrote into buf (truncated to buflen - 1, empty if capture was never
 * set up or nothing was written). */
static void otp_capture_end(FILE *stream, FILE *tmp, int saved_fd, char *buf, size_t buflen)
{
  buf[0] = '\0';
  fflush(stream);
  if (saved_fd >= 0)
  {
    dup2(saved_fd, fileno(stream));
    close(saved_fd);
  }
  if (tmp)
  {
    rewind(tmp);
    size_t n = fread(buf, 1, buflen - 1, tmp);
    buf[n] = '\0';
    fclose(tmp);
  }
}

static int keypair_stream_pad(unsigned char *buf, size_t size, FILE *src,
                              FILE *dst1, FILE *dst2, const char *what)
{
  size_t left = size;
  while (left > 0)
  {
    size_t want = (left < KEYPAIR_CHUNK) ? left : KEYPAIR_CHUNK;
    if (fread(buf, 1, want, src) != want)
    {
      fprintf(stderr, "Error reading %s key chunk\n", what);
      return -1;
    }
    if (fwrite(buf, 1, want, dst1) != want || fwrite(buf, 1, want, dst2) != want)
    {
      fprintf(stderr, "Error writing %s key: %s\n", what, strerror(errno));
      return -1;
    }
    keypair_spinner_tick();
    left -= want;
  }
  return 0;
}

/* Read back and compare two just-closed key files that are supposed to be
 * exact mirrors of the same pad (path1 = one party's encryption_for_peer,
 * path2 = the peer's decryption_from_that_party - the same bytes, written
 * via two separate fwrite() calls per chunk in keypair_stream_pad()). A
 * successful fclose() only proves libc accepted the bytes, not that both
 * copies are correctly and identically on disk; this is the same
 * read-back discipline every other durable write in this codebase applies
 * before trusting what it just wrote, adapted here to a pad generated by
 * this run rather than an existing source file to compare against.
 * Returns 0 if identical, -1 on any mismatch or I/O error. */
static int keypair_verify_mirror(const char *path1, const char *path2)
{
  FILE *f1 = fopen(path1, "rb");
  FILE *f2 = fopen(path2, "rb");
  int ok = (f1 && f2) ? 1 : 0;
  unsigned char buf1[65536], buf2[65536];
  while (ok)
  {
    size_t n1 = fread(buf1, 1, sizeof(buf1), f1);
    size_t n2 = fread(buf2, 1, sizeof(buf2), f2);
    if (n1 != n2 || memcmp(buf1, buf2, n1) != 0 || ferror(f1) || ferror(f2))
    {
      ok = 0;
      break;
    }
    if (n1 == 0)
      break; /* both at EOF, everything compared equal so far */
  }
  if (f1)
    fclose(f1);
  if (f2)
    fclose(f2);
  return ok ? 0 : -1;
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  /* Windows opens stdin/stdout in text mode by default, which corrupts
   * binary data: it rewrites \n<->\r\n and treats the first 0x1A (Ctrl-Z)
   * as end-of-file. Every byte this tool moves through the standard
   * streams is arbitrary binary - ciphertext on the way out, plaintext on
   * the way in - and the keychain encrypt/decrypt path is handed these
   * very streams as input/output. Without this a message containing 0x0A,
   * 0x0D or 0x1A would be silently mangled. The file paths already use
   * O_BINARY; this is the matching fix for the streams themselves, and
   * must run before any byte is read or written. */
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  /* **************************************************************************
   *  Handles -h (--help) command                                             *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))
  {
    /* Command parameter signatures are highlighted in yellow, terminal
     * only - redirected help output stays plain text, like every other
     * colored output here. Each description renders on its own line
     * below its parameters. */
    const char *hl = otp_stdout_is_tty() ? OTP_YELLOW : "";
    const char *rs = otp_stdout_is_tty() ? OTP_RESET : "";
    static const char *cmds[][2] = {
        {"--new-key-pair <size_in_MB> <part_a_name> <part_b_name> (or -nk)",
         "Generate a pair of one-time pads for two correspondents, writing each party's encryption/decryption keys into its own <name>_keys directory. Reads <size_in_MB> megabytes of randomness per pad from piped stdin; with no pipe, offers to draw the pair from the randomness vault instead, if it holds enough (2x <size_in_MB>).\n  From the vault (no pipe): otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>"},
        {"--contact <name> --encrypt (or -c)",
         "Encrypt stdin to stdout, consuming the contact's encryption key"},
        {"--contact <name> --decrypt (or -c)",
         "Decrypt stdin to stdout, consuming the contact's decryption key"},
        {"--add-contact <name> [<enc_key_file> <dec_key_file>] (or -ac)",
         "Add a contact to the keychain (optionally with key files)"},
        {"--remove-contact <name> (or -rc)",
         "Remove a contact from the keychain"},
        {"--has-contact <name> (or -hc)",
         "Check if a contact exists"},
        {"--list-contacts (or -lc)",
         "List all contacts"},
        {"--show-contact <name> (or -sc)",
         "Show contact details"},
        {"-y (or --assume-delivered)",
         "Skip the delivery-confirmation prompt. Each direction's messages must be processed in the exact order sent, complete, exactly once; the per-message metadata rejects violations at decrypt time before any key is spent, but only the correspondents can confirm, out of band, that a delivered message actually reached its reader - so before spending key on any message after the first, otp asks on the terminal whether the previous message arrived intact, and cancels (keys untouched) unless answered yes. Pass -y (or set OTP_ASSUME_DELIVERED=1) after confirming out of band - required when no terminal is available."},
        {"--with-ack-file",
         "Optional, alongside -c <name> --encrypt or --decrypt. Writes that message's source_id, in lowercase hex, to <contact>_<seq>_ack_ref.sent.txt on encrypt or <contact>_<seq>_ack.received.txt on decrypt, and prints on stderr what to do with it. The source_id is the 16-byte chunk at the head of the message's key range: spent with that range but never used as pad, so it can be disclosed after the fact without revealing anything that protected the plaintext, while only a holder of the mirrored key at that exact offset could produce it. The recipient sends their value back in the clear; a sender whose file matches knows that exact message was decrypted. The file is published before any key is spent - a reference that cannot be written aborts the operation with nothing consumed, since the source_id cannot be recovered once its key range is destroyed. It confirms decryption, not that a human read it, and it is not a receipt provable to a third party - the sender knows the value too. Both correspondents must agree to acknowledge this way; nothing in the protocol requires it."},
        {"--status <name> [--porcelain] (or -st)",
         "Report a contact's per-direction state, verified from the disk files themselves (the key file's physical size is the authority, never the metadata alone): messages sent/received, key bytes remaining, metadata consistency, whether an interrupted run left a committed message the next operation will redeliver instead of processing new input, and whether the last sent/received message still awaits delivery confirmation. --porcelain prints stable key=value lines for scripts. Strictly read-only. Exit codes: 0 clean and ready, 4 redelivery pending, 5 delivery confirmation outstanding, 6 key material rolled back (re-key the contact), 1 error."},
        {"--recover-last <name> --sent|--received (or -rl)",
         "Stream the kept safety copy of the last delivered payload to stdout: --sent re-emits the exact ciphertext of the last encrypt (for re-transmission), --received the exact plaintext of the last decrypt (for re-delivery to an application). Read-only and repeatable: the copy is never deleted by this command - only the next confirmed operation in that direction removes it. Exit codes: 0 copy streamed, 2 no copy exists (nothing awaits confirmation), 1 error."},
        {"--add-rand-to-vault <size_in_MB>",
         "Read <size_in_MB> megabytes of randomness from stdin and store it in the keychain's randomness vault (.keychain/_randomness): appended if the vault already exists, created with mode 0600 if not. The bytes are stored exactly as read, byte for byte. Not tied to any contact - the vault is not itself consumed or tracked as key material, just accumulated storage. On success reports OK followed by how much was just added and the vault's new running total."},
    };
    /* Commands that do not touch the keychain at all - no contact, no
     * key accounting, no metadata - listed apart so the separation is
     * visible in the help itself, not just in the prose. */
    static const char *utils[][3] = {
        {"--xor <bytes> (or -x)",
         "DO NOT USE THIS METHOD TO ENCRYPT/DECRYPT FOR A CONTACT, USE THE KEYCHAIN ENCRYPT/DECRYPT COMMAND",
         "XOR stdin against <bytes> - any readable file or character device, read from its offset 0 - and write the result to stdout. Raw plumbing, outside the keychain: <bytes> is only read, never truncated, and no metadata, sequence number, source_id or delivery confirmation is involved - so nothing here prevents the same bytes from covering a second message, which breaks the one-time-pad guarantee. XOR is its own inverse, so the same invocation encrypts and decrypts. Exits 1 if <bytes> is shorter than the input (the bytes already written stand)."},
    };
    /* Banner: the title as a black-on-white chip, one space of padding
     * inside the highlight on each side, flush against the left edge.
     * Piped output gets the plain line instead. */
    printf("\n\n");
    if (otp_stdout_is_tty())
      printf("%s otp-toolkit v1.7.0 - One Time Pad toolkit %s\n", OTP_BLACK_ON_WHITE, OTP_RESET);
    else
      puts("otp-toolkit v1.7.0 - One Time Pad toolkit");
    otp_print_wrapped("\nEncrypt and decrypt messages with the one-time pad, the only cipher with proven perfect secrecy. Messages stream from stdin to stdout; the key material lives in a keychain of contacts, each holding one pad per direction. Every operation consumes its key bytes and physically destroys them - crash-safely, so no key range can ever cover two messages, even across interrupted runs.\n\nUses:");
    /* Each use is a heading, the shell line itself, and an optional
     * note. Only the shell line is colored; it goes through the same
     * wrapper as everything else here, so a long command wraps and
     * indents its continuation exactly like the surrounding text. */
    static const char *uses[][3] = {
        {"Encrypt (using keychain):",
         "echo \"plain\" | otp -c <contact_name> --encrypt > cipher.txt",
         NULL},
        {"Decrypt (using keychain):",
         "cat cipher.txt | otp -c <contact_name> --decrypt > plain.txt",
         NULL},
        {"Generate key pair:",
         "cat /dev/urandom | otp --new-key-pair <size_in_MB> <part_a_name> <part_b_name>",
         "Writes each party's keys into its own directory, named for the correspondent:\n  <part_a_name>_keys/encryption_for_<part_b_name>.key and <part_a_name>_keys/decryption_from_<part_b_name>.key\n  <part_b_name>_keys/encryption_for_<part_a_name>.key and <part_b_name>_keys/decryption_from_<part_a_name>.key\nRun with no pipe (stdin a terminal), it offers the randomness vault instead of refusing, when the vault holds enough (2x <size_in_MB>, since a pair draws two independent pads)."},
        {"Add randomness to the vault:",
         "cat /dev/urandom | otp --add-rand-to-vault <size_in_MB>",
         "Appends (or creates) .keychain/_randomness with that much randomness, stored exactly as read."},
        {"Mix two sources of randomness into the vault:",
         "cat /dev/urandom | otp --xor /dev/hwrng | otp --add-rand-to-vault 10",
         "XORing independent sources yields randomness at least as unpredictable as the strongest of them, so a biased or compromised source cannot weaken the result. /dev/hwrng is the raw hardware RNG (present only on machines that have one, and typically root-readable); any independent source works - two draws from the same one add nothing."},
    };
    const char *cmd_color = otp_stdout_is_tty() ? OTP_GREEN : "";
    for (size_t i = 0; i < sizeof(uses) / sizeof(uses[0]); i++)
    {
      printf("  %s\n", uses[i][0]);
      otp_print_wrapped_colored(uses[i][1], 4, cmd_color);
      if (uses[i][2])
        otp_print_wrapped_indented(uses[i][2], 4);
      putchar('\n');
    }
    otp_print_wrapped("Keychain Commands:");
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
    {
      printf("  %s%s%s\n", hl, cmds[i][0], rs);
      otp_print_wrapped_indented(cmds[i][1], 4);
    }
    otp_print_wrapped("\nUtility commands:");
    /* The warning goes directly under the signature, before the
     * description, and in red on a terminal: this command is the one
     * way to produce ciphertext the keychain never accounts for, so a
     * reader must meet that before the convenience of the mode. */
    const char *warn_color = otp_stdout_is_tty() ? OTP_RED : "";
    for (size_t i = 0; i < sizeof(utils) / sizeof(utils[0]); i++)
    {
      printf("  %s%s%s\n", hl, utils[i][0], rs);
      otp_print_wrapped_colored(utils[i][1], 4, warn_color);
      otp_print_wrapped_indented(utils[i][2], 4);
    }
    otp_print_wrapped("\nSafety copies:\n  Each keychain encrypt/decrypt keeps an exact copy of its stdout payload at .keychain/<contact>.last_sent (ciphertext) or .keychain/<contact>.last_received (plaintext), so a forgotten redirect cannot lose a message whose key bytes are already destroyed. The copy is removed automatically (no manual cleanup needed) when the next operation in that direction confirms delivery; if delivery is rejected, otp offers to recover the copy to a file. --recover-last streams the copy at any time without consuming it.\n\nExternal integration:\n  Programs driving otp need no library: --status answers, from the disk files alone, everything a client must know before its next operation (is a crash-recovery redelivery pending? is the previous message still unconfirmed?), --recover-last re-emits the kept copy for re-transmission or re-delivery, and the -c exit codes report each operation's outcome: 0 processed, 8 redelivered, 1 error - and on --decrypt, the metadata validation codes 1 invalid source_id, 2 invalid seq, 3 invalid offset, 4 source_id+seq, 7 source_id+offset, 6 seq+offset, 5 all three (a rejected message consumes no key). Delivery confirmation stays with the integrating program: pass -y on the next operation once the peer acknowledged the previous message. See the \"External Integrations\" section of README.md for the full send/receive flow.\n");
    return 0;
  }

  /* **************************************************************************
   *  Handles keychain commands                                               *
   * *********************************************************************** */

  if (argc >= 3 && (strcmp(argv[1], "-ac") == 0 || strcmp(argv[1], "--add-contact") == 0))
  {
    load_keychain();
    int result;
    int tty_out = otp_stdout_is_tty();
    char outbuf[4096], errbuf[4096];
    int saved_out_fd, saved_err_fd;
    FILE *outcap, *errcap;

    // Check if key files are provided
    if (argc >= 5)
    {
      // Add contact with keys: otp -ac <name> <enc_key_file> <dec_key_file>
      outcap = otp_capture_begin(stdout, &saved_out_fd);
      errcap = otp_capture_begin(stderr, &saved_err_fd);
      result = add_contact_with_keys(argv[2], argv[3], argv[4]);
      otp_capture_end(stdout, outcap, saved_out_fd, outbuf, sizeof outbuf);
      otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    }
    else if (argc == 4)
    {
      /* One key file is never enough: a contact needs both an encryption
       * and a decryption key. Silently ignoring the argument here would
       * create a keyless contact and report success, leaving the user
       * believing their key was loaded. */
      fprintf(stderr, "Error: Both an encryption and a decryption key file are required\n");
      fprintf(stderr, "Usage: otp --add-contact <name> [<enc_key_file> <dec_key_file>]\n");
      cleanup_keychain();
      return 1;
    }
    else
    {
      // Add contact without keys: otp -ac <name>
      outcap = otp_capture_begin(stdout, &saved_out_fd);
      errcap = otp_capture_begin(stderr, &saved_err_fd);
      result = add_contact(argv[2]);
      otp_capture_end(stdout, outcap, saved_out_fd, outbuf, sizeof outbuf);
      otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    }

    if (result == 0)
    {
      printf("%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
      /* add_contact() (unlike add_contact_with_keys()) prints no summary
       * of its own, so outbuf is empty on that path - fall back to a
       * plain one-liner. */
      if (!outbuf[0])
        snprintf(outbuf, sizeof(outbuf), "Contact '%s' added successfully\n", argv[2]);
      printf("%s%s%s", tty_out ? OTP_YELLOW : "", outbuf, tty_out ? OTP_RESET : "");
      if (errbuf[0])
        fputs(errbuf, stderr); /* a non-fatal warning (name re-use, mirrored pad) can
                                 * still accompany a successful add */
    }
    else
    {
      fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
      if (errbuf[0])
        fprintf(stderr, "%s%s%s", tty_out ? OTP_RED : "", errbuf, tty_out ? OTP_RESET : "");
    }

    cleanup_keychain();
    return result == 0 ? 0 : 1;
  }

  if (argc >= 3 && (strcmp(argv[1], "-rc") == 0 || strcmp(argv[1], "--remove-contact") == 0))
  {
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    char errbuf[4096];
    int saved_err_fd;
    FILE *errcap = otp_capture_begin(stderr, &saved_err_fd);
    int result = remove_contact(argv[2]);
    otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    cleanup_keychain();

    if (result == 0)
    {
      printf("%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
      printf("%sContact '%s' removed successfully%s\n",
             tty_out ? OTP_YELLOW : "", argv[2], tty_out ? OTP_RESET : "");
    }
    else
    {
      fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
      if (errbuf[0])
        fprintf(stderr, "%s%s%s", tty_out ? OTP_RED : "", errbuf, tty_out ? OTP_RESET : "");
    }
    return result == 0 ? 0 : 1;
  }

  if (argc >= 3 && (strcmp(argv[1], "-hc") == 0 || strcmp(argv[1], "--has-contact") == 0))
  {
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    int exists = has_contact(argv[2]);
    cleanup_keychain();
    if (exists)
    {
      printf("%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
      printf("%sContact '%s' exists%s\n", tty_out ? OTP_YELLOW : "", argv[2], tty_out ? OTP_RESET : "");
      return 0;
    }
    else
    {
      fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
      fprintf(stderr, "%sContact '%s' does not exist%s\n",
              tty_out ? OTP_RED : "", argv[2], tty_out ? OTP_RESET : "");
      return 1;
    }
  }

  if (argc >= 2 && (strcmp(argv[1], "-lc") == 0 || strcmp(argv[1], "--list-contacts") == 0))
  {
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    char outbuf[4096];
    int saved_out_fd;
    FILE *outcap = otp_capture_begin(stdout, &saved_out_fd);
    list_contacts();
    otp_capture_end(stdout, outcap, saved_out_fd, outbuf, sizeof outbuf);
    cleanup_keychain();

    /* Listing a keychain never fails - it is always exactly the current
     * contents, empty or not - so this only ever reports OK. */
    printf("%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
    printf("%s%s%s", tty_out ? OTP_YELLOW : "", outbuf, tty_out ? OTP_RESET : "");
    return 0;
  }

  if (argc >= 3 && (strcmp(argv[1], "-sc") == 0 || strcmp(argv[1], "--show-contact") == 0))
  {
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    char outbuf[4096], errbuf[4096];
    int saved_out_fd, saved_err_fd;
    FILE *outcap = otp_capture_begin(stdout, &saved_out_fd);
    FILE *errcap = otp_capture_begin(stderr, &saved_err_fd);
    show_contact(argv[2]);
    otp_capture_end(stdout, outcap, saved_out_fd, outbuf, sizeof outbuf);
    otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    cleanup_keychain();

    /* show_contact() is void - the only signal that it failed is whether
     * it wrote to stderr (its one error path, contact not found). */
    if (!errbuf[0])
    {
      printf("%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
      printf("%s%s%s", tty_out ? OTP_YELLOW : "", outbuf, tty_out ? OTP_RESET : "");
      return 0;
    }
    else
    {
      fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
      fprintf(stderr, "%s%s%s", tty_out ? OTP_RED : "", errbuf, tty_out ? OTP_RESET : "");
      return 1;
    }
  }

  if (argc >= 3 && (strcmp(argv[1], "-st") == 0 || strcmp(argv[1], "--status") == 0))
  {
    int porcelain = 0;
    for (int i = 3; i < argc; i++)
    {
      if (strcmp(argv[i], "--porcelain") == 0)
        porcelain = 1;
    }
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    char errbuf[4096];
    int saved_err_fd;
    /* --status's stdout carries the state itself - the human-readable
     * report, or --porcelain's key=value lines a script parses exactly -
     * so unlike the commands below it stays untouched. Only stderr,
     * where the plain error path (contact not found) writes its one
     * "Error: ..." line, is captured, so FAIL can be ordered ahead of it. */
    FILE *errcap = otp_capture_begin(stderr, &saved_err_fd);
    int result = keychain_status(argv[2], porcelain);
    otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    cleanup_keychain();
    /* keychain_status returns the documented exit code directly (0 clean,
     * 4 redelivery pending, 5 confirmation outstanding, 6 rolled back);
     * only its error return (-1) is folded to the generic 1. */
    if (result < 0)
    {
      fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
      if (errbuf[0])
        fprintf(stderr, "%s%s%s", tty_out ? OTP_RED : "", errbuf, tty_out ? OTP_RESET : "");
      return 1;
    }
    if (errbuf[0])
      fputs(errbuf, stderr);
    return result;
  }

  if (argc >= 3 && (strcmp(argv[1], "-rl") == 0 || strcmp(argv[1], "--recover-last") == 0))
  {
    int sent = (argc >= 4 && strcmp(argv[3], "--sent") == 0);
    int received = (argc >= 4 && strcmp(argv[3], "--received") == 0);
    if (!sent && !received)
    {
      fprintf(stderr, "Error: --recover-last requires --sent or --received\n");
      fprintf(stderr, "Usage: otp --recover-last <contact_name> --sent|--received\n");
      return 1;
    }
    load_keychain();
    int tty_out = otp_stdout_is_tty();
    char errbuf[4096];
    int saved_err_fd;
    /* The recovered payload streams to the real stdout untouched - it's
     * the deliverable a script redirects to a file - so OK/FAIL and the
     * summary/reason (already on stderr from keychain_recover_last())
     * are captured and recolored on stderr only, never mixed into it. */
    FILE *errcap = otp_capture_begin(stderr, &saved_err_fd);
    int result = keychain_recover_last(argv[2], sent, stdout);
    otp_capture_end(stderr, errcap, saved_err_fd, errbuf, sizeof errbuf);
    cleanup_keychain();

    if (result == 0)
    {
      fprintf(stderr, "%sOK%s\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
      if (errbuf[0])
        fprintf(stderr, "%s%s%s", tty_out ? OTP_YELLOW : "", errbuf, tty_out ? OTP_RESET : "");
      return 0;
    }
    /* Exit 2 = no copy exists (nothing awaits confirmation) - distinct
     * from an error so scripts can use this as an existence probe, so
     * its message stays plain rather than styled as a failure. */
    if (result == KEYCHAIN_RECOVER_NO_COPY)
    {
      if (errbuf[0])
        fputs(errbuf, stderr);
      return KEYCHAIN_RECOVER_NO_COPY;
    }
    fprintf(stderr, "%sFAIL%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
    if (errbuf[0])
      fprintf(stderr, "%s%s%s", tty_out ? OTP_RED : "", errbuf, tty_out ? OTP_RESET : "");
    return 1;
  }

  /* **************************************************************************
   *  Handles -c (--contact) command for encryption/decryption                *
   * *********************************************************************** */

  if (argc >= 3 && (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--contact") == 0))
  {
    if (argc < 4)
    {
      fprintf(stderr, "Error: -c option requires contact name and --encrypt or --decrypt flag\n");
      fprintf(stderr, "Usage: otp -c <contact_name> --encrypt|--decrypt [-y|--assume-delivered]\n");
      return 1;
    }
  }

  if (argc >= 4 && (strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--contact") == 0))
  {
    const char *contact_name = argv[2];
    int is_encrypt = 0;
    int is_decrypt = 0;

    // Check for --encrypt or --decrypt flag
    for (int i = 3; i < argc; i++)
    {
      if (strcmp(argv[i], "--encrypt") == 0)
      {
        is_encrypt = 1;
      }
      else if (strcmp(argv[i], "--decrypt") == 0)
      {
        is_decrypt = 1;
      }
      else if (strcmp(argv[i], "-y") == 0 || strcmp(argv[i], "--assume-delivered") == 0)
      {
        /* The operator confirmed out of band that the previous message in
         * this direction arrived intact, so the interactive
         * delivery-confirmation prompt is skipped. Required for scripts:
         * with no terminal to ask on, the gate fails closed. */
        keychain_set_assume_delivered(1);
      }
      else if (strcmp(argv[i], "--with-ack-file") == 0)
      {
        /* Handled inside cipher.c: the reference has to be published
         * before any key is spent, which is a point only the operation
         * itself can act on. */
        cipher_set_ack_file(1);
      }
    }

    if (!is_encrypt && !is_decrypt)
    {
      fprintf(stderr, "Error: Must specify --encrypt or --decrypt with -c option\n");
      return 1;
    }

    if (is_encrypt && is_decrypt)
    {
      fprintf(stderr, "Error: Cannot specify both --encrypt and --decrypt\n");
      return 1;
    }

    load_keychain();

    int result;
    if (is_encrypt)
    {
      result = encrypt_with_contact(contact_name, stdin, stdout);
    }
    else
    {
      result = decrypt_with_contact(contact_name, stdin, stdout);
    }

    cleanup_keychain();

    /* Map to a stable exit status. KEYCHAIN_REDELIVERED (8) gets its
     * own, non-zero code: the command produced valid output, but that
     * output is a recovered message from an interrupted earlier run and
     * this invocation's input was NOT processed. A script must be able
     * to tell that apart from success without parsing stderr. The
     * metadata validation codes (1-7, --decrypt only; see cipher.h) pass
     * through unchanged - they name exactly which of source_id/seq/
     * offset failed, and guarantee no key material was consumed. All
     * other failures fold to the generic 1. */
    if (result > 0)
      return result;
    return result == KEYCHAIN_OK ? 0 : 1;
  }

  /* **************************************************************************
   *  Handles -x (--xor) command                                              *
   * *********************************************************************** */

  if (argc >= 2 && (strcmp(argv[1], "-x") == 0 || strcmp(argv[1], "--xor") == 0))
  {
    if (argc < 3)
    {
      fprintf(stderr, "Error: --xor requires <bytes>, a file or device to XOR against\n");
      fprintf(stderr, "Usage: cat data | otp --xor <bytes> > out\n");
      return 1;
    }

    /* Raw XOR: stdin against the bytes of <bytes>, from its offset 0,
     * straight to stdout. Deliberately outside the keychain - it reads
     * that file and never truncates it, keeps no metadata, no
     * sequence, no source_id, and asks for no delivery confirmation - so
     * NOTHING here stops the same key bytes from covering a second
     * message. That accounting is what -c <contact> --encrypt/--decrypt
     * exists to provide; this is the plumbing primitive for keys managed
     * entirely by the caller. XOR is its own inverse, so the same
     * invocation encrypts and decrypts. */
    FILE *keyfile = fopen(argv[2], "rb");
    if (!keyfile)
    {
      fprintf(stderr, "Error: Cannot open '%s': %s\n", argv[2], strerror(errno));
      return 1;
    }

    unsigned char *data = malloc(XOR_CHUNK_SIZE);
    unsigned char *pad = malloc(XOR_CHUNK_SIZE);
    if (!data || !pad)
    {
      fprintf(stderr, "Error: Failed to allocate memory\n");
      free(data);
      free(pad);
      fclose(keyfile);
      return 1;
    }

    /* Streamed in chunks so the key and the input are never held in
     * memory whole - the same reason encrypt/decrypt stream. The input
     * length is unknowable in advance (stdin is typically a pipe), so a
     * key that runs out is caught mid-stream: the chunks already written
     * stand, and the error says how much was covered before the key
     * ended. */
    int rc = 0;
    size_t written = 0;
    size_t n;
    while ((n = fread(data, 1, XOR_CHUNK_SIZE, stdin)) > 0)
    {
      if (fread(pad, 1, n, keyfile) != n)
      {
        fprintf(stderr,
                "Error: '%s' is shorter than the input; %zu bytes were XORed "
                "before it ran out\n",
                argv[2], written);
        rc = 1;
        break;
      }
      for (size_t i = 0; i < n; i++)
        data[i] ^= pad[i];
      if (fwrite(data, 1, n, stdout) != n)
      {
        fprintf(stderr, "Error: Failed to write to stdout: %s\n", strerror(errno));
        rc = 1;
        break;
      }
      written += n;
    }
    if (rc == 0 && ferror(stdin))
    {
      fprintf(stderr, "Error: Failed to read from stdin: %s\n", strerror(errno));
      rc = 1;
    }

    free(data);
    free(pad);
    fclose(keyfile);
    if (fflush(stdout) != 0)
    {
      fprintf(stderr, "Error: Failed to write to stdout: %s\n", strerror(errno));
      rc = 1;
    }
    return rc;
  }

  /* **************************************************************************
   *  Handles --add-rand-to-vault command                                     *
   * *********************************************************************** */

  if (argc >= 3 && strcmp(argv[1], "--add-rand-to-vault") == 0)
  {
    /* Same rationale as --new-key-pair below: randomness is read from
     * stdin, so a terminal there means no randomness source was piped
     * in - refused before the vault file is even opened. */
    if (otp_stdin_is_tty())
    {
      fprintf(stderr,
              "Error: --add-rand-to-vault reads randomness from stdin, but stdin is a "
              "terminal.\nPipe in a randomness source, e.g.:\n"
              "  cat /dev/urandom | otp --add-rand-to-vault %s\n",
              argv[2]);
      return 1;
    }

    const char *size_str = argv[2];
    char *endptr = NULL;
    double size_mb = strtod(size_str, &endptr);
    if (endptr == size_str || size_mb <= 0)
    {
      fprintf(stderr, "Invalid size %s MB\n", size_str);
      return 1;
    }
    /* Range-check before converting: a size_mb larger than size_t can
     * represent makes the conversion below undefined, not merely wrong. */
    if (size_mb > (double)(SIZE_MAX / (1024 * 1024)))
    {
      fprintf(stderr, "Size too large: %s MB\n", size_str);
      return 1;
    }
    size_t size = (size_t)(size_mb * 1024 * 1024 + 0.5); // round
    if (size == 0)
    {
      fprintf(stderr, "Size too small: %s MB results in 0 bytes\n", size_str);
      return 1;
    }

    size_t total = 0;
    if (add_rand_to_vault(size, &total) != 0)
      return 1;

    /* OK in green, the summary in yellow (piped output stays plain text,
     * like every other colored report here) - the amount just added and
     * the vault's new total, both in MB (to match the command's own
     * <size_in_MB> unit) and exact bytes (to match the byte-exactness
     * the vault itself guarantees). */
    int tty_out = otp_stdout_is_tty();
    printf("%sOK%s\n\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
    printf("%sAdded: %s MB (%zu bytes)%s\n", tty_out ? OTP_YELLOW : "", size_str, size, tty_out ? OTP_RESET : "");
    printf("%sVault total: %.2f MB (%zu bytes)%s\n", tty_out ? OTP_YELLOW : "", (double)total / (1024.0 * 1024.0), total, tty_out ? OTP_RESET : "");
    return 0;
  }

  /* **************************************************************************
   *  Handles -nk (--new-key-pair) command                                    *
   * *********************************************************************** */

  if (argc >= 5 && (strcmp(argv[1], "-nk") == 0 || strcmp(argv[1], "--new-key-pair") == 0))
  {
    const char *size_str = argv[2];
    char *endptr = NULL;
    double size_mb = strtod(size_str, &endptr);
    if (endptr == size_str || size_mb <= 0)
    {
      fprintf(stderr, "Invalid size %s MB\n", size_str);
      return 1;
    }
    const char *part_a = argv[3];
    const char *part_b = argv[4];
    /* part_a/part_b are built verbatim into paths below - the per-party
     * <name>_keys/ directory and files, and (when drawing from the
     * vault) the pending-claim artifact's name inside .keychain/ - the
     * same way a contact's name is, so they need the same validation a
     * contact name gets. Without this, a name like "../../evil" could
     * write key material outside the intended directory, and - via the
     * vault path, where commit_stage_open() unlinks whatever already
     * exists at its target first - delete an arbitrary file the caller
     * can write to. Checked before anything is created or the vault is
     * touched. */
    if (!is_valid_contact_name(part_a))
    {
      fprintf(stderr,
              "Error: Invalid party name '%s' - names must be 1-%d characters and may not be "
              "\".\" or \"..\", contain a path separator (/ or \\), any of : * ? \" < > | = , "
              "or control characters\n",
              part_a, MAX_NAME_LENGTH - 1);
      return 1;
    }
    if (!is_valid_contact_name(part_b))
    {
      fprintf(stderr,
              "Error: Invalid party name '%s' - names must be 1-%d characters and may not be "
              "\".\" or \"..\", contain a path separator (/ or \\), any of : * ? \" < > | = , "
              "or control characters\n",
              part_b, MAX_NAME_LENGTH - 1);
      return 1;
    }
    /* Range-check before converting: a size_mb larger than size_t can
     * represent makes the conversion below undefined, not merely wrong. */
    if (size_mb > (double)(SIZE_MAX / (1024 * 1024)))
    {
      fprintf(stderr, "Size too large: %s MB\n", size_str);
      return 1;
    }
    size_t size = (size_t)(size_mb * 1024 * 1024 + 0.5); // round
    if (size == 0)
    {
      fprintf(stderr, "Size too small: %s MB results in 0 bytes\n", size_str);
      return 1;
    }

    /* Two independent pads, each `size` bytes, are consumed to produce the
     * pair - see the streaming loop below - so drawing from the vault
     * instead of stdin needs 2*size bytes of it available. */
    size_t vault_required = size * 2;
    if (vault_required / 2 != size)
    {
      fprintf(stderr, "Size too large: %s MB\n", size_str);
      return 1;
    }

    /* Key material normally streams from a piped stdin (unchanged below).
     * With no pipe, the randomness vault (.keychain/_randomness, filled by
     * --add-rand-to-vault) is offered as a source instead of refusing
     * outright - but only after checking for a leftover claim from an
     * interrupted earlier vault-sourced run for this exact pair (see
     * vault_claim_recover() in keychain.c), so a crash between claiming
     * vault bytes and finishing the key files can always be resumed rather
     * than silently drawing fresh randomness on top. Checked before any
     * directory or file is created. */
    int use_vault = 0;
    char vault_pending_path[600] = {0};
    if (otp_stdin_is_tty())
    {
      load_keychain();
      int rec = vault_claim_recover(part_a, part_b, vault_pending_path, sizeof vault_pending_path);
      cleanup_keychain();
      if (rec < 0)
        return 1; /* vault_claim_recover() already reported why */

      if (rec == 1)
      {
        use_vault = 1; /* an earlier claim for this exact pair is waiting to be delivered */
      }
      else
      {
        load_keychain();
        size_t vault_size = 0;
        int vault_rc = get_vault_size(&vault_size);
        cleanup_keychain();
        if (vault_rc != 0)
          return 1;

        if (vault_size == 0 || vault_size < vault_required)
        {
          fprintf(stderr,
                  "There is no randomness vault size above 1 bit, please provide randomness via stdin\n"
                  "Example: cat /dev/urandom | otp --new-key-pair %s %s %s\n",
                  size_str, part_a, part_b);
          return 1;
        }

        int tty_out = otp_stdout_is_tty();
        printf("\nThere is currently %.2f MB of random key available in the vault.\n\n"
               "Use randomness vault for key generation? [y/N]: ",
               (double)vault_size / (1024.0 * 1024.0));
        fflush(stdout);

        char resp[16] = {0};
        if (!fgets(resp, sizeof resp, stdin) || (resp[0] != 'y' && resp[0] != 'Y'))
        {
          fprintf(stderr, "%sOperation canceled%s\n", tty_out ? OTP_RED : "", tty_out ? OTP_RESET : "");
          return 1;
        }

        load_keychain();
        int claim_rc = vault_claim(vault_required, part_a, part_b, vault_pending_path, sizeof vault_pending_path);
        cleanup_keychain();
        if (claim_rc != 0)
          return 1;
        use_vault = 1;
      }
    }

    /* Part A's encryption key is Part B's decryption key and vice versa,
     * so each of the two pads read from stdin is written to two files.
     * Each party gets its own directory, <name>_keys/, holding that
     * party's encryption_for_<peer>.key and decryption_from_<peer>.key -
     * the pair of files that party receives, ready to hand over as one
     * unit, each named for the correspondent it is used with. Directories
     * are created 0700 (a pre-existing one is reused); files in this
     * order, all O_EXCL and 0600. */
    char names[KEYPAIR_FILES][256] = {{0}};
    FILE *files[KEYPAIR_FILES] = {0};
    char dirs[KEYPAIR_DIRS][256] = {{0}}; /* only directories created by this run */
    const char *parts[KEYPAIR_DIRS] = {part_a, part_b};

    for (int i = 0; i < KEYPAIR_DIRS; i++)
    {
      char dir[256];
      if (snprintf(dir, sizeof dir, "%s_keys", parts[i]) >= (int)sizeof dir)
      {
        fprintf(stderr, "Error: name %s is too long\n", parts[i]);
        keypair_cleanup(files, names, dirs);
        return 1;
      }
      if (mkdir(dir, 0700) == 0)
        memcpy(dirs[i], dir, sizeof dir);
      else if (errno != EEXIST)
      {
        fprintf(stderr, "Error creating directory %s: %s\n", dir, strerror(errno));
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    /* Each file is named for the correspondent it is used with, so both
     * party names appear in every path; check truncation so a truncated
     * path can never be created or removed. */
    if (snprintf(names[0], sizeof names[0], "%s_keys/encryption_for_%s.key", part_a, part_b) >= (int)sizeof names[0] ||
        snprintf(names[1], sizeof names[1], "%s_keys/decryption_from_%s.key", part_a, part_b) >= (int)sizeof names[1] ||
        snprintf(names[2], sizeof names[2], "%s_keys/encryption_for_%s.key", part_b, part_a) >= (int)sizeof names[2] ||
        snprintf(names[3], sizeof names[3], "%s_keys/decryption_from_%s.key", part_b, part_a) >= (int)sizeof names[3])
    {
      fprintf(stderr, "Error: key file path too long\n");
      memset(names, 0, sizeof names); // truncated paths are not ours to remove
      keypair_cleanup(files, names, dirs);
      return 1;
    }

    for (int i = 0; i < KEYPAIR_FILES; i++)
    {
      int kfd = open(names[i], O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);
      if (kfd < 0)
      {
        fprintf(stderr, "Error creating %s: %s\n", names[i], strerror(errno));
        /* Neither this file nor the ones after it were created by this
         * run; a pre-existing file at any of those paths is not ours to
         * remove. */
        for (int j = i; j < KEYPAIR_FILES; j++)
          names[j][0] = '\0';
        keypair_cleanup(files, names, dirs);
        return 1;
      }
      files[i] = fdopen(kfd, "wb");
      if (!files[i])
      {
        fprintf(stderr, "Error fdopen %s: %s\n", names[i], strerror(errno));
        close(kfd);
        /* names[i] itself was just created, so it is removed; the ones
         * after it never were. */
        for (int j = i + 1; j < KEYPAIR_FILES; j++)
          names[j][0] = '\0';
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    /* Progress line, printed before the long streaming phase. The green
     * OK below only appears after every byte has been written and
     * flushed, so its absence tells the user a mid-generation
     * interruption left the keys unusable. On a terminal a spinner
     * (ticked once per streamed chunk) shows the work is progressing;
     * the trailing space is the placeholder its backspace overwrites. */
    int tty_out = otp_stdout_is_tty();
    printf("Generating key pair of %s MB... (wait for the %sOK%s message, if you don't see it, it failed) ",
           size_str, tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");
    if (tty_out)
    {
      keypair_spinner_frame = 0;
      fputs(" ", stdout);
    }
    fflush(stdout);

    /* Vault-sourced generation streams from the already-claimed, verified
     * pending artifact instead of stdin; everything else about the
     * streaming loop below is unchanged. */
    FILE *pad_source = stdin;
    if (use_vault)
    {
      pad_source = fopen(vault_pending_path, "rb");
      if (!pad_source)
      {
        fprintf(stderr, "Error: Cannot reopen claimed vault randomness '%s': %s\n",
                vault_pending_path, strerror(errno));
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    unsigned char *buf = malloc(KEYPAIR_CHUNK);
    if (!buf)
    {
      fputs("\n", stdout); /* finish the progress line before the error */
      keypair_spinner_frame = -1;
      fprintf(stderr, "Memory allocation failed\n");
      if (use_vault)
        fclose(pad_source);
      keypair_cleanup(files, names, dirs);
      return 1;
    }

    /* Pad 1 -> A's encryption key and B's decryption key.
     * Pad 2 -> A's decryption key and B's encryption key. */
    if (keypair_stream_pad(buf, size, pad_source, files[0], files[3], "first") != 0 ||
        keypair_stream_pad(buf, size, pad_source, files[1], files[2], "second") != 0)
    {
      fputs("\n", stdout);
      keypair_spinner_frame = -1;
      free(buf);
      if (use_vault)
        fclose(pad_source);
      keypair_cleanup(files, names, dirs);
      return 1;
    }
    free(buf);
    if (use_vault)
      fclose(pad_source);

    /* fsync before fclose: fclose()'s own flush reports a failed write
     * that fwrite() alone cannot (a key file silently truncated by a full
     * disk), but does not by itself force the bytes to stable storage -
     * every other durable write in this codebase fsyncs explicitly, and
     * freshly generated, irreplaceable key material deserves the same
     * guarantee before it is reported as done. */
    for (int i = 0; i < KEYPAIR_FILES; i++)
    {
      int failed = (fflush(files[i]) != 0 || otp_fsync(fileno(files[i])) != 0);
      if (fclose(files[i]) != 0)
        failed = 1;
      files[i] = NULL;
      if (failed)
      {
        fputs("\n", stdout);
        keypair_spinner_frame = -1;
        fprintf(stderr, "Error writing %s: %s\n", names[i], strerror(errno));
        keypair_cleanup(files, names, dirs);
        return 1;
      }
    }

    /* Read back and verify: each pad was written twice (once per party),
     * and the two copies must be byte-identical - see
     * keypair_verify_mirror(). This is the read-back check every other
     * durable write here gets, closing the one gap left after fsync
     * above (bytes correctly flushed to storage but not correctly the
     * bytes intended, e.g. from a bit flip in transit to disk). */
    if (keypair_verify_mirror(names[0], names[3]) != 0 ||
        keypair_verify_mirror(names[1], names[2]) != 0)
    {
      fputs("\n", stdout);
      keypair_spinner_frame = -1;
      fprintf(stderr, "Error: generated key files failed verification (the two copies of a pad do not match)\n");
      keypair_cleanup(files, names, dirs);
      return 1;
    }

    /* Every key file is safely on disk - the claimed vault bytes are fully
     * delivered, so the pending artifact recording that claim is no longer
     * needed for recovery. */
    if (use_vault)
    {
      load_keychain();
      vault_claim_release(vault_pending_path);
      cleanup_keychain();
    }

    /* Success report: the green OK the progress line promised, on its
     * own line after a blank one, then each party's directory in yellow
     * with its two keys in green. On a terminal the spinner is wiped
     * first so no stray frame remains at the end of the progress line. */
    keypair_spinner_frame = -1;
    if (tty_out)
      fputs("\b \b", stdout);
    printf("\n\n%sOK%s\n\n", tty_out ? OTP_GREEN : "", tty_out ? OTP_RESET : "");

    for (int d = 0; d < KEYPAIR_DIRS; d++)
    {
      printf("%s%s_keys/%s\n", tty_out ? OTP_YELLOW : "", parts[d], tty_out ? OTP_RESET : "");
      for (int f = 0; f < 2; f++)
      {
        const char *full = names[d * 2 + f];
        const char *base = strrchr(full, '/');
        base = base ? base + 1 : full;
        printf("   %s%s%s (%zu bytes)\n",
               tty_out ? OTP_GREEN : "", base, tty_out ? OTP_RESET : "", size);
      }
      putchar('\n');
    }
    printf("Store/Share the keys safely!\n");
    return 0;
  }


  /* **************************************************************************
   *  Anything else is not a recognized command                               *
   * *********************************************************************** */

  fprintf(stderr, "Error: Unknown command. Use -h for help.\n");
  return 1;
}
