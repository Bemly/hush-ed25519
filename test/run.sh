#!/bin/sh
# hush-ed25519 test runner
# Run inside a BusyBox container:
#   docker run --rm -v "$PWD":/w busybox:musl sh /w/test/run.sh

cd "$(dirname "$0")/.." || exit 1
. ./lib/ed25519.sh

PASS=0
FAIL=0

_TMP="${TMPDIR:-/tmp}/ed25519-test.$$"
mkdir -p "$_TMP" || exit 1

assert_eq() {
	_got="$1" _want="$2" _msg="$3"
	if [ "$_got" = "$_want" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf 'FAIL: %s\n  want: %s\n  got:  %s\n' "$_msg" "$_want" "$_got"
	fi
}

assert_ok() {
	_code=$? _msg="$1"
	if [ $_code -eq 0 ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf 'FAIL: %s (exit=%d)\n' "$_msg" $_code
	fi
}

assert_fail() {
	_code=$? _msg="$1"
	if [ $_code -ne 0 ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf 'FAIL: %s (expected non-zero exit)\n' "$_msg"
	fi
}

assert_ne() {
	_a="$1" _b="$2" _msg="$3"
	if [ "$_a" != "$_b" ]; then
		PASS=$((PASS + 1))
	else
		FAIL=$((FAIL + 1))
		printf 'FAIL: %s (values are equal)\n' "$_msg"
	fi
}

# ---- tests ----
for _f in test/test_*.sh; do
	. "./$_f"
done

rm -rf "$_TMP"

printf '\n%s passed, %s failed, %s total\n' "$PASS" "$FAIL" $((PASS + FAIL))
[ "$FAIL" -eq 0 ] || exit 1
