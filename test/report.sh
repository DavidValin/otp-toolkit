#!/bin/sh

# Renders test-report.html: runs every test script in the same order as
# `make build` and writes a standalone HTML report - one expandable
# section per script with a colored PASS/FAIL badge, the captured output
# (assertion lines colorized), and the script's own source, indentation
# preserved. Unlike make, a failing script does not stop the run: every
# script is executed so the report is always complete - and each script's
# assertion lines are also streamed live to the console (colorized the
# same way, when it's a terminal) as that script produces them, one test
# case at a time, so the console log is as complete a record of every
# PASS/FAIL as the HTML report is.
#
# Usage: sh test/report.sh  (or `make test`)
#
# The report is written to the directory the script is invoked from; the
# tests themselves always run from the repo root, which is where they
# expect ./bin/otp and create their working files.
#
# This script itself is POSIX sh + sed/grep only, so it runs everywhere
# the test suite does. The test scripts, however, are executed with bash
# when it is available: that is the interpreter the Makefile always runs
# them through, and some of their behavior differs under a strict POSIX
# sh (macOS sh is bash 3.2 in POSIX mode, Ubuntu sh is dash). Falling
# back to sh only matters on systems without bash, where the scripts'
# #!/bin/sh line is the suite's best effort anyway.

OUT=$(pwd)/test-report.html
cd "$(dirname "$0")/.." || exit 1

if command -v bash >/dev/null 2>&1; then
  TEST_SHELL=bash
else
  TEST_SHELL=sh
fi

if [ ! -x bin/otp ] && [ ! -f bin/otp.exe ]; then
  echo "bin/otp not found - run 'make build' first" >&2
  exit 1
fi

TESTS="otp keychain commit lock metadata msgmeta confirm lastcopy truncate status recoverlast randvault vaultkeypair reporthtml"
ESC_CHAR=$(printf '\033')
REPO_URL="https://github.com/DavidValin/otp"

# Colors for the console echo of each script's captured output below - same
# convention every individual test/*.test.sh script uses for its own PASS/
# FAIL lines (disabled when stdout isn't a terminal, e.g. under `make` or CI).
if [ -t 1 ]; then
  GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); YELLOW=$(printf '\033[33m'); NC=$(printf '\033[0m')
else
  GREEN=; RED=; YELLOW=; NC=
fi

# sed fully buffers its output (rather than flushing per line) whenever
# that output isn't itself a terminal - which colorize_console's is not,
# piped into as it is below - so without disabling that, every one of a
# script's PASS/FAIL lines would sit in sed's buffer and appear all at
# once when the script exits, defeating the point of streaming them live
# as each test case actually runs.
#
# The flag for that is spelled differently across sed implementations -
# GNU and OpenBSD sed both use -u; FreeBSD, NetBSD, and macOS sed instead
# use -l, and neither accepts the other's flag - so probe for the one
# this sed actually supports rather than guessing from the OS. Getting
# it wrong isn't just cosmetic: sed is the last stage of a pipeline
# reading a live test script's output below, so an unsupported flag
# makes it exit immediately, and the resulting broken pipe sends SIGPIPE
# back through tee to the test script itself before it can finish.
# Falling back to no flag at all is buffered but still correct.
if printf '' | sed -u 's/x/x/' >/dev/null 2>&1; then
  SED_UNBUF="-u"
elif printf '' | sed -l 's/x/x/' >/dev/null 2>&1; then
  SED_UNBUF="-l"
else
  SED_UNBUF=""
fi

# Version as declared in the cli.c banner, so the report can never drift
# from the source on a version bump.
VERSION=$(sed -n 's/.*otp-toolkit v\([0-9][0-9.]*\).*/\1/p' src/cli.c | head -1)

. test/reportlib.sh

BODY=$(mktemp) || exit 1
trap 'rm -f "$BODY"' EXIT

total=0; failed=0; pass_assert=0; fail_assert=0
run_date=$(date '+%Y-%m-%d %H:%M:%S')

for t in $TESTS; do
  script="test/$t.test.sh"
  total=$((total+1))
  # Every suite's header line gets a blank line ahead of it and is painted
  # yellow, so each suite boundary is easy to spot scrolling through a
  # full run. Each suite's own PASS/FAIL content below is untouched.
  printf '\n%s - %s%s\n' "$YELLOW" "$script" "$NC"
  t0=$(date +%s)

  # Stream each assertion line to the console (colorized) as the script
  # produces it, one test case at a time, while tee also captures the
  # same bytes to $OUTTMP for the HTML report below. A pipeline's $? is
  # its last stage's (tee's), never the test script's, so the subshell
  # writes the script's real exit code to $RC_FILE as a side channel.
  OUTTMP=$(mktemp) || exit 1
  RC_FILE=$(mktemp) || exit 1
  ( $TEST_SHELL "$script" 2>&1; echo $? > "$RC_FILE" ) | tee "$OUTTMP" | colorize_console
  rc=$(cat "$RC_FILE")
  rm -f "$RC_FILE"
  t1=$(date +%s)

  # Tests already suppress color when stdout is not a terminal - and are
  # always piped above, so they always take that branch regardless of the
  # real terminal - but strip ANSI sequences anyway so a stray code can
  # never corrupt the HTML.
  clean=$(sed "s/${ESC_CHAR}\[[0-9;]*m//g" "$OUTTMP")
  rm -f "$OUTTMP"
  p=$(printf '%s\n' "$clean" | grep -c ' - PASS')
  f=$(printf '%s\n' "$clean" | grep -c '! FAIL')
  pass_assert=$((pass_assert+p)); fail_assert=$((fail_assert+f))

  if [ "$rc" -eq 0 ]; then
    badge=pass; label=PASS; echo "   ok ($p assertions)"
  else
    badge=fail; label=FAIL; failed=$((failed+1)); echo "   FAILED (exit $rc)"
  fi
  extra=""
  [ "$f" -gt 0 ] && extra=", $f failed"

  {
    echo "<details class=\"$badge\" open>"
    echo "<summary><span class=\"badge $badge\">$label</span> <code>$script</code><span class=\"meta\">$p passed$extra &middot; $((t1-t0))s &middot; exit $rc</span></summary>"
    echo "<h3>Output</h3>"
    printf '<pre class="block">'
    printf '%s\n' "$clean" | html_escape | colorize_result
    printf '</pre>\n'
    echo "<details class=\"inner\">"
    echo "<summary>Source</summary>"
    printf '<pre class="block src">'
    html_escape < "$script"
    printf '</pre>\n'
    echo "</details>"
    echo "</details>"
  } >> "$BODY"
done

cases=$((pass_assert+fail_assert))
if [ "$failed" -eq 0 ]; then
  verdict="All $total test groups passed"; vclass=pass
else
  verdict="$failed of $total test groups failed"; vclass=fail
fi
if [ "$fail_assert" -eq 0 ]; then
  cverdict="All $cases test cases passed"; cvclass=pass
else
  cverdict="$fail_assert of $cases test cases failed"; cvclass=fail
fi

{
  cat <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>otp-toolkit v$VERSION test report</title>
<style>
:root {
  --bg: #ffffff; --fg: #1a1a1a; --muted: #6a6a6a; --line: #d8d8d8;
  --block-bg: #f6f6f6; --pass: #1a7f37; --fail: #c72c2c;
  --pass-bg: #e3f2e6; --fail-bg: #fbe4e4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16181c; --fg: #e4e4e4; --muted: #9a9a9a; --line: #3a3d42;
    --block-bg: #1f2227; --pass: #4bc76c; --fail: #f2635f;
    --pass-bg: #1d3323; --fail-bg: #3b2222;
  }
}
body { background: var(--bg); color: var(--fg); margin: 0 auto; padding: 2rem 1rem 4rem;
       max-width: 60rem; font: 15px/1.5 system-ui, sans-serif; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
.repo { font-size: .95rem; font-weight: 400; color: var(--muted); }
.repo a { color: inherit; }
.repo a:hover { color: var(--fg); }
h3 { font-size: .8rem; text-transform: uppercase; letter-spacing: .06em;
     color: var(--muted); margin: 1rem 0 .35rem; }
.subtitle { color: var(--muted); margin: 0 0 1.5rem; }
.verdict { display: inline-block; padding: .35rem .8rem; border-radius: .4rem;
           font-weight: 600; margin: 0 0 1.5rem; }
.verdict.pass { color: var(--pass); background: var(--pass-bg); }
.verdict.fail { color: var(--fail); background: var(--fail-bg); }
.verdict + .verdict { margin-left: .5rem; }
details { border: 1px solid var(--line); border-radius: .5rem;
          margin: 0 0 .6rem; overflow: hidden; }
summary { cursor: pointer; padding: .6rem .9rem; display: flex;
          align-items: center; gap: .6rem; flex-wrap: wrap; }
summary:hover { background: var(--block-bg); }
summary code { font-weight: 600; }
details[open] > summary { border-bottom: 1px solid var(--line); }
details > *:not(summary) { margin-left: .9rem; margin-right: .9rem; }
details > pre:last-child { margin-bottom: .9rem; }
.badge { font: 700 .72rem/1 ui-monospace, monospace; padding: .3rem .5rem;
         border-radius: .3rem; }
.badge.pass { color: var(--pass); background: var(--pass-bg); }
.badge.fail { color: var(--fail); background: var(--fail-bg); }
.meta { color: var(--muted); font-size: .8rem; margin-left: auto; }
details.inner { border: none; border-radius: 0; margin: 1rem .9rem .9rem; }
details.inner > summary { padding: 0; display: block; font-size: .8rem;
  font-weight: 600; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); border-bottom: none; }
details.inner > summary:hover { background: none; color: var(--fg); }
details.inner[open] > summary { margin-bottom: .35rem; }
details.inner > pre { margin-left: 0; margin-right: 0; }
pre.block { background: var(--block-bg); border: 1px solid var(--line);
            border-radius: .4rem; padding: .7rem .9rem; overflow-x: auto;
            font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            tab-size: 4; }
b.pass { color: var(--pass); } b.fail { color: var(--fail); }
</style>
</head>
<body>
<h1>otp-toolkit v$VERSION <span class="repo">- <a href="$REPO_URL">$REPO_URL</a></span></h1>
<p class="subtitle">$run_date &middot; click "Source" inside a group to see its test script</p>
<div class="verdict $vclass">$verdict</div>
<div class="verdict $cvclass">$cverdict</div>
EOF
  cat "$BODY"
  echo "</body>"
  echo "</html>"
} > "$OUT"

echo
echo "Report written to $OUT"
[ "$failed" -eq 0 ]
