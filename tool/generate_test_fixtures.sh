#!/usr/bin/env bash
# Regenerates the TLS fixtures used by the unit tests in `test/`.
#
# Requirements: bash + OpenSSL 1.1.1 or newer (Git for Windows ships both).
#
#   bash tool/generate_test_fixtures.sh
#
# Produces, in `test/fixtures/`:
#   root_ca.pem, intermediate_ca.pem      CA chain (RSA 2048)
#   server_a1.pem / server_a2.pem         two distinct certificates sharing ONE key (server_a.key)
#   server_b.pem                          certificate with a different key (server_b.key)
#   server_a1_chain.pem, server_b_chain.pem  leaf + intermediate, as a server presents them
#   selfsigned.pem / selfsigned.key       self-signed EC P-256 leaf
#   v1.pem                                X.509 **version 1** certificate (no version field, no extensions)
#   pins.json                             SPKI SHA-256 pins computed independently with OpenSSL
#
# All keys are throw-away test keys. NEVER use them for anything else.
set -euo pipefail

# Git Bash on Windows would otherwise rewrite "/CN=..." into a Windows path.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# A native openssl.exe (Git for Windows) cannot read MSYS-style "/c/..." or "/tmp"
# paths once path conversion is disabled, so hand it mixed Windows paths instead.
native_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
OUT="$(native_path "$ROOT_DIR/test/fixtures")"
TMP="$(native_path "$(mktemp -d)")"
trap 'rm -rf "$TMP"' EXIT
DAYS=36500

# Runs openssl quietly, but prints its stderr if it fails.
ossl() {
  openssl "$@" 2>"$TMP/ossl.err" || { cat "$TMP/ossl.err" >&2; return 1; }
}

mkdir -p "$OUT"
rm -f "$OUT"/*.pem "$OUT"/*.key "$OUT"/pins.json

# --- Root CA -----------------------------------------------------------------
ossl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/root.key" \
  -out "$OUT/root_ca.pem" -days $DAYS -subj "/CN=Pinning Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Intermediate CA ---------------------------------------------------------
ossl req -newkey rsa:2048 -nodes -keyout "$TMP/int.key" -out "$TMP/int.csr" \
  -subj "/CN=Pinning Test Intermediate CA"
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$TMP/int.ext"
ossl x509 -req -in "$TMP/int.csr" -CA "$OUT/root_ca.pem" -CAkey "$TMP/root.key" \
  -CAcreateserial -CAserial "$TMP/ca.srl" -out "$OUT/intermediate_ca.pem" \
  -days $DAYS -extfile "$TMP/int.ext"

# --- Leaf certificates -------------------------------------------------------
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$TMP/leaf.ext"

issue_leaf() { # <csr> <out.pem> <serial>
  ossl x509 -req -in "$1" -CA "$OUT/intermediate_ca.pem" -CAkey "$TMP/int.key" \
    -set_serial "$3" -out "$2" -days $DAYS -extfile "$TMP/leaf.ext"
}

# Key A, issued twice (simulates certificate renewal that keeps the same key).
ossl genrsa -out "$OUT/server_a.key" 2048
ossl req -new -key "$OUT/server_a.key" -out "$TMP/a.csr" -subj "/CN=localhost"
issue_leaf "$TMP/a.csr" "$OUT/server_a1.pem" 1001
issue_leaf "$TMP/a.csr" "$OUT/server_a2.pem" 1002

# Key B (simulates key rotation).
ossl genrsa -out "$OUT/server_b.key" 2048
ossl req -new -key "$OUT/server_b.key" -out "$TMP/b.csr" -subj "/CN=localhost"
issue_leaf "$TMP/b.csr" "$OUT/server_b.pem" 2001

cat "$OUT/server_a1.pem" "$OUT/intermediate_ca.pem" > "$OUT/server_a1_chain.pem"
cat "$OUT/server_b.pem" "$OUT/intermediate_ca.pem" > "$OUT/server_b_chain.pem"

# --- Self-signed EC leaf -----------------------------------------------------
ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/selfsigned.key" -out "$OUT/selfsigned.pem" -days $DAYS \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# --- X.509 v1 certificate (no explicit version field) ------------------------
printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=v1\n' > "$TMP/v1.cnf"
ossl req -x509 -x509v1 -config "$TMP/v1.cnf" -newkey rsa:2048 -nodes \
  -keyout "$TMP/v1.key" -out "$OUT/v1.pem" -days $DAYS
if ! openssl x509 -in "$OUT/v1.pem" -noout -text | grep -q "Version: 1 (0x0)"; then
  echo "ERROR: v1.pem is not an X.509 v1 certificate with this OpenSSL build" >&2
  exit 1
fi

# --- Ground-truth SPKI pins (computed by OpenSSL, not by the package) --------
pin() {
  ossl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary | openssl base64 -A
}
{
  echo "{"
  echo "  \"root_ca\": \"$(pin "$OUT/root_ca.pem")\","
  echo "  \"intermediate_ca\": \"$(pin "$OUT/intermediate_ca.pem")\","
  echo "  \"server_a1\": \"$(pin "$OUT/server_a1.pem")\","
  echo "  \"server_a2\": \"$(pin "$OUT/server_a2.pem")\","
  echo "  \"server_b\": \"$(pin "$OUT/server_b.pem")\","
  echo "  \"selfsigned\": \"$(pin "$OUT/selfsigned.pem")\","
  echo "  \"v1\": \"$(pin "$OUT/v1.pem")\""
  echo "}"
} > "$OUT/pins.json"

echo "Fixtures written to $OUT"
