# Public API behaviour: key derivation, stdin, aliases, error paths.

# ---- ed25519_seed_hex: repeat secret, truncate to 32 bytes ----
assert_eq "$(ed25519_seed_hex test)" \
	"$(printf '%s' testtesttesttesttesttesttesttest | xxd -p -c 256)" \
	"seed_hex: 4-byte secret repeated"
assert_eq "$(ed25519_seed_hex abc)" \
	"$(printf '%s' abcabcabcabcabcabcabcabcabcabcab | xxd -p -c 256)" \
	"seed_hex: 3-byte secret truncated to 32"
# a 32-char secret is treated as 32 ASCII bytes, not as hex
assert_eq "$(ed25519_seed_hex 0123456789abcdef0123456789abcdef)" \
	"$(printf '%s' 0123456789abcdef0123456789abcdef | xxd -p -c 256)" \
	"seed_hex: 32-byte secret used as-is"
ed25519_seed_hex "" 2>/dev/null
assert_fail "seed_hex: empty secret rejected"

# ---- pub derivation matches RFC 8032 vector 1 ----
_SEED1=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
_PUB1=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
assert_eq "$(ed25519_pub_hex $_SEED1)" "$_PUB1" "pub_hex: RFC 8032 vector 1"
assert_eq "$(ed_pub $_SEED1)" "$_PUB1" "alias ed_pub"

# ---- sign / verify round trip with a file and with stdin ----
printf 'hello hush' >"$_TMP/api1"
_sig="$(ed25519_sign_hex $_SEED1 "$_TMP/api1")"
assert_eq "${#_sig}" 128 "sign_hex: 128 hex chars"
ed25519_verify_hex "$_PUB1" "$_TMP/api1" "$_sig" 2>/dev/null
assert_ok "verify_hex: file round trip"

_sig_stdin="$(printf 'hello hush' | ed25519_sign_hex $_SEED1 -)"
assert_eq "$_sig_stdin" "$_sig" "sign_hex: stdin matches file"
printf 'hello hush' | ed25519_verify_hex "$_PUB1" - "$_sig" 2>/dev/null
assert_ok "verify_hex: stdin round trip"

assert_eq "$(ed_sign $_SEED1 "$_TMP/api1")" "$_sig" "alias ed_sign"

# ---- QQ Bot flavour: derive seed from the app secret, then sign/verify ----
_qqsig="$(ed25519_sign_secret "my-app-secret" "$_TMP/api1")"
_qqpub="$(ed25519_pub_hex "$(ed25519_seed_hex "my-app-secret")")"
ed25519_verify_hex "$_qqpub" "$_TMP/api1" "$_qqsig" 2>/dev/null
assert_ok "sign_secret / verify_hex"
ed25519_verify_secret "my-app-secret" "$_TMP/api1" "$_qqsig" 2>/dev/null
assert_ok "verify_secret"

# ---- error paths ----
ed25519_pub_hex zz 2>/dev/null
assert_fail "pub_hex: bad hex rejected"
ed25519_pub_hex 9d61 2>/dev/null
assert_fail "pub_hex: short seed rejected"
ed25519_sign_hex $_SEED1 "$_TMP/does-not-exist" 2>/dev/null
assert_fail "sign_hex: missing message file rejected"
ed25519_verify_hex "$_PUB1" "$_TMP/api1" 2>/dev/null
assert_fail "verify_hex: missing signature rejected"
ed25519_verify_hex "$_PUB1" "$_TMP/api1" abc 2>/dev/null
assert_fail "verify_hex: malformed signature rejected"
[ -n "$_ED25519_ERROR" ]
assert_ok "error message recorded in _ED25519_ERROR"
