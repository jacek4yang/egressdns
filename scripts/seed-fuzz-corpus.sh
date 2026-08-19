#!/usr/bin/env bash
#
# Build a starting corpus for the fuzz targets from the committed test fixtures.
#
#   ./scripts/seed-fuzz-corpus.sh

set -Eeuo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
corpus="$root/fuzz/corpus"

mkdir -p \
    "$corpus/seed_parser" \
    "$corpus/cloudflare_prefix_json" \
    "$corpus/config_toml" \
    "$corpus/dataset_parser" \
    "$corpus/admin_protocol" \
    "$corpus/dns_message"

cp "$root"/tests/fixtures/seed_*.txt   "$corpus/seed_parser/" 2>/dev/null || true
cp "$root"/tests/fixtures/seed_html.html "$corpus/seed_parser/" 2>/dev/null || true
cp "$root"/tests/fixtures/cloudflare_ips_api.json "$corpus/cloudflare_prefix_json/" 2>/dev/null || true
cp "$root"/config/*.toml "$corpus/config_toml/" 2>/dev/null || true

cat > "$corpus/dataset_parser/hosts" <<'HOSTS'
# sample hosts file
10.0.0.1 gw.corp.test gateway
2001:db8::1 v6.corp.test
HOSTS

for command in status reload upstreams network cache-stats flush-all; do
    printf '{"command":"%s","args":[]}\n' "$command" > "$corpus/admin_protocol/$command.json"
done

printf '{"command":"flush-name","args":["example.com"]}\n' > "$corpus/admin_protocol/flush-name.json"
printf '{"command":"cloudflare","args":["status"]}\n'      > "$corpus/admin_protocol/cloudflare.json"

# A minimal well-formed DNS query: id=0x1234, RD set, QDCOUNT=1, "example.com" A IN.
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
    > "$corpus/dns_message/query-a"

printf 'seeded corpora under %s\n' "$corpus"
