# Edge cases: canonical encodings, small-order keys, S >= L, temp file hygiene.

_SEED=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
_PUB=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
printf 'boundary' >"$_TMP/b1"
_SIG="$(ed25519_sign_hex $_SEED "$_TMP/b1")"
_R="$(printf '%s' "$_SIG" | cut -c1-64)"

# S = L exactly is non-canonical (valid range is 0 <= S < L)
ed25519_verify_hex "$_PUB" "$_TMP/b1" \
	"${_R}edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010" 2>/dev/null
assert_fail "S = L rejected"

# S with the high bit set (S >> L) is rejected
ed25519_verify_hex "$_PUB" "$_TMP/b1" \
	"${_R}ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" 2>/dev/null
assert_fail "S > L rejected"

# y >= p is not a canonical point encoding
ed25519_verify_hex "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
	"$_TMP/b1" "$_SIG" 2>/dev/null
assert_fail "non-canonical public key rejected"

# the identity public key would make every (R = identity, S = 0) signature valid
ed25519_verify_hex "0100000000000000000000000000000000000000000000000000000000000000" \
	"$_TMP/b1" "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" 2>/dev/null
assert_fail "identity public key rejected (small-order forgery)"

# uppercase hex must be handled the same as lowercase
_UP="$(printf '%s' "$_SEED" | cut -c1-64 | tr 'a-f' 'A-F')"
assert_eq "$(ed25519_pub_hex "$_UP")" "$_PUB" "uppercase seed accepted"

# no leftover scratch directories after 5 signatures + 5 verifies
_before="$(ls -d "${TMPDIR:-/tmp}"/ed25519.* 2>/dev/null | wc -l)"
_i=0
while [ $_i -lt 5 ]; do
	ed25519_verify_hex "$_PUB" "$_TMP/b1" "$_SIG" 2>/dev/null
	_i=$((_i + 1))
done
_after="$(ls -d "${TMPDIR:-/tmp}"/ed25519.* 2>/dev/null | wc -l)"
assert_eq "$_after" "$_before" "no temp directories leaked"
