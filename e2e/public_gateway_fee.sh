#!/usr/bin/env bash
# Mine past the activation height with two gateways on regtest: a public one whose secondary
# coinbase tag the pool was given, and one with no tag, as a miner runs beside its own node.
# Check that the pool charges the tagged gateway's shares the public gateway fee and
# reassigns the charged work to the miner on the untagged gateway: every pooled coinbase pays
# the split a copy of the pool's arithmetic computes from the ledger, the pool's address
# receives only the remainder that arithmetic leaves, at least one coinbase pays the public
# gateway's miner less than its work alone earns, and at least one pays the own-gateway
# miner more.
#
#                              datum_gateway A (tag "public")
#   bitcoind (Knots, BLAKE2b) <    ^ alice           |
#                       ^ RPC  datum_gateway B (no tag) - DATUM +-> ratum-prime -> RPC
#                                     ^ bob                (--public-gateway-fee-bps 5000,
#                                                           --public-gateway-fee-subsidy-bps 10000)
#
# usage: e2e/public_gateway_fee.sh [--keep]
#
# Needs a Bitcoin Knots build with the BLAKE2b change; the gateway is this workspace's
# ratum-gateway crate unless DATUM_GATEWAY names another build (the C gateway, say):
#   BITCOIND        default ~/src/bitcoin/build/bin/bitcoind
#   BITCOIN_CLI     default ~/src/bitcoin/build/bin/bitcoin-cli
#   DATUM_GATEWAY   default the ratum-gateway crate in this workspace, built below
#   ALICE_SHARES    shares from the miner on the public gateway before checking, default 6
#   BOB_SHARES      shares from the miner on the own gateway, default 2
#   TIMEOUT         seconds to wait for them, default 5400
#
# Exits 0 only if every pooled coinbase matches the split with the fee and the subsidy, the
# pool's address received exactly the remainder, alice was charged the fee in at least one
# block, and bob was paid the subsidy in at least one.

set -euo pipefail

BITCOIND=${BITCOIND:-$HOME/src/bitcoin/build/bin/bitcoind}
BITCOIN_CLI=${BITCOIN_CLI:-$HOME/src/bitcoin/build/bin/bitcoin-cli}
DATUM_GATEWAY=${DATUM_GATEWAY:-}
ALICE_SHARES=${ALICE_SHARES:-6}
BOB_SHARES=${BOB_SHARES:-2}
TIMEOUT=${TIMEOUT:-5400}
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

ACTIVATION_HEIGHT=20

# 5000 basis points: half of alice's work is charged, so the fee and the subsidy are large
# enough to show in the few shares a CPU miner produces.
FEE_BPS=5000
# The whole fee is reassigned: the pool keeps none, so a coinbase with own-gateway work in
# the window leaves the pool address no remainder at all.
SUBSIDY_BPS=10000
PUBLIC_TAG=public

ALICE=bcrt1q5xs6rgdp5xs6rgdp5xs6rgdp5xs6rgdpa854mc
BOB=bcrt1qk2et9v4jk2et9v4jk2et9v4jk2et9v4jldyv0a
GATEWAY_ADDRESS=bcrt1q6n2df4x56n2df4x56n2df4x56n2df4x5jumwup
POOL_ADDRESS=bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080

# Every share is difficulty 1: the pool's floor is 1 and the vardiff target is set so far
# above what a CPU miner reaches that the gateway never raises it. The window is far above
# the work this run produces, so the split for every block is computable from a prefix of
# the ledger.
WINDOW_FLOOR=1048576
MIN_PAYOUT=1
VARDIFF_TARGET=4

CORES=$(nproc)
ALICE_CPUS=0-$(( CORES / 2 - 1 ))
BOB_CPUS=$(( CORES / 2 ))-$(( CORES - 1 ))

. "$(dirname "$0")/lib.sh"

ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ratum-public-fee-XXXXXX")

RPC_PORT=$(free_port 18400 150)
POOL_PORT=$(free_port 28900 90)
STRATUM_PORT_A=$(free_port 23300 90)
STRATUM_PORT_B=$(free_port 23400 90)
API_PORT_A=$(free_port 7100 90)
API_PORT_B=$(free_port 7200 90)
PIDS=()

trap cleanup EXIT

require_tools jq taskset python3

# ledger::split with the public gateway fee, in Python. The window a coinbase was built from
# is some prefix of the ledger (see multi_miner.sh), so every prefix is tried. Prints the
# prefix that reproduces the paid outputs, then alice's and bob's amounts under it with the
# fee and without it.
cat > "$WORK/match_split.py" <<'MATCHPY'
import sys

ledger, max_prefix, value, min_payout, pool, public_tag, fee_bps, subsidy_bps, alice, bob = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]),
    sys.argv[5], sys.argv[6], int(sys.argv[7]), int(sys.argv[8]), sys.argv[9], sys.argv[10],
)

paid = {}
for line in sys.stdin:
    if line.split():
        identity, amount = line.split()
        paid[identity] = int(amount)

def split(work, own, fee_bps, subsidy_bps):
    charged = {i: (w - own.get(i, 0)) * fee_bps // 10000 for i, w in work.items()}
    fee_work = sum(charged.values())
    own_total = sum(own.values())
    reassigned = fee_work * subsidy_bps // 10000 if own_total else 0
    given = 0
    weights = {}
    for identity, w in work.items():
        extra = reassigned * own.get(identity, 0) // own_total if own_total else 0
        given += extra
        weights[identity] = w - charged[identity] + extra
    retained = fee_work - given
    kept = sorted(weights.items(), key=lambda kv: (-kv[1], kv[0]))[:512]
    left_work = sum(w for _, w in kept) + retained
    while kept:
        if left_work == 0:
            kept = []
            break
        if value * kept[-1][1] // left_work >= min_payout:
            break
        left_work -= kept[-1][1]
        kept.pop()
    left = value
    out = {}
    for identity, w in kept:
        if left_work == 0:
            break
        amount = left * w // left_work
        left -= amount
        left_work -= w
        if amount:
            out[identity] = amount
    return out, left

with open(ledger) as f:
    shares = [line.split() for line in f]

work, own = {}, {}
for prefix in range(0, max_prefix + 1):
    if prefix:
        parts = shares[prefix - 1]
        if len(parts) >= 4:
            identity = parts[2].split('.')[0]
            difficulty = int(parts[1])
            tag = parts[4] if len(parts) > 4 else ''
            work[identity] = work.get(identity, 0) + difficulty
            if tag != public_tag:
                own[identity] = own.get(identity, 0) + difficulty
    out, remainder = split(work, own, fee_bps, subsidy_bps)
    expected = dict(out)
    expected[pool] = expected.get(pool, 0) + remainder
    expected = {k: v for k, v in expected.items() if v}
    if expected == paid:
        plain, _ = split(work, own, 0, 0)
        print(prefix, out.get(alice, 0), plain.get(alice, 0), out.get(bob, 0), plain.get(bob, 0))
        break
else:
    sys.exit(1)
MATCHPY

DATUM_GATEWAY=${DATUM_GATEWAY:-$ROOT/target/release/ratum-gateway}
build_release

start_node

step "mining $ACTIVATION_HEIGHT blocks with the node, through the activation"
cli generatetoaddress "$ACTIVATION_HEIGHT" "$POOL_ADDRESS" >/dev/null

step "starting ratum-prime on port $POOL_PORT, fee $FEE_BPS bps on shares tagged $PUBLIC_TAG, subsidy $SUBSIDY_BPS bps"
mkdir -p "$WORK/pool"
RUST_LOG="${RUST_LOG:-debug}" \
"$ROOT/target/release/ratum-prime" \
    --listen "127.0.0.1:$POOL_PORT" \
    --data-dir "$WORK/pool" \
    --rpc "http://127.0.0.1:$RPC_PORT" --rpc-user ratum --rpc-pass ratumtest \
    --payout-address "$POOL_ADDRESS" \
    --coinbase-tag RATUM \
    --public-gateway-fee-bps "$FEE_BPS" --public-gateway-fee-subsidy-bps "$SUBSIDY_BPS" \
    --public-gateway-tag "$PUBLIC_TAG" \
    --min-diff 1 --min-payout "$MIN_PAYOUT" --poll 1 --window-floor "$WINDOW_FLOOR" \
    > "$WORK/pool.log" 2>&1 &
POOL_PID=$!
PIDS+=($POOL_PID)

for _ in $(seq 1 60); do
    grep -q 'listening on' "$WORK/pool.log" 2>/dev/null && break
    sleep 0.5
done
grep -q 'listening on' "$WORK/pool.log" \
    || fail "the pool never listened on 127.0.0.1:$POOL_PORT; see $WORK/pool.log"
grep -q 'public gateway fee:' "$WORK/pool.log" \
    || fail "the pool did not report the public gateway fee at startup; see $WORK/pool.log"
PUBKEY=$(awk '{for (i = 1; i < NF; i++) if ($i == "pool_pubkey:") {print $(i + 1); exit}}' \
    "$WORK/pool.log")
[ -n "$PUBKEY" ] || fail "the pool never printed its public key; see $WORK/pool.log"

# Gateway A is the public one: it tags its coinbases. Gateway B is what a miner runs beside
# its own node: the secondary tag left at its default, which is empty.
start_gateway() {
    local name=$1 stratum_port=$2 api_port=$3 tag_json=$4
    cat > "$WORK/gateway-$name.json" <<EOF
{
  "bitcoind": {
    "rpcuser": "ratum",
    "rpcpassword": "ratumtest",
    "rpcurl": "http://127.0.0.1:$RPC_PORT",
    "notify_fallback": true
  },
  "stratum": {
    "listen_port": $stratum_port,
    "vardiff_min": 1,
    "vardiff_target_shares_min": $VARDIFF_TARGET
  },
  "mining": {
    "pool_address": "$GATEWAY_ADDRESS",
    "coinbase_tag_primary": "RATUM"$tag_json
  },
  "api": { "admin_password": "", "listen_port": $api_port, "modify_conf": false },
  "logger": { "log_to_console": true, "log_to_file": false, "log_level_console": 1 },
  "datum": {
    "pool_host": "127.0.0.1",
    "pool_port": $POOL_PORT,
    "pool_pubkey": "$PUBKEY",
    "pool_pass_workers": true,
    "pool_pass_full_users": true,
    "pooled_mining_only": true
  }
}
EOF
    "$DATUM_GATEWAY" -c "$WORK/gateway-$name.json" > "$WORK/gateway-$name.log" 2>&1 &
    PIDS+=($!)

    for _ in $(seq 1 60); do
        grep -q 'Stratum V1 Server Init complete' "$WORK/gateway-$name.log" 2>/dev/null && break
        sleep 0.5
    done
    grep -q 'DATUM Server MOTD' "$WORK/gateway-$name.log" \
        || fail "gateway $name never completed the handshake; see $WORK/gateway-$name.log"
}

step "starting gateway A on stratum port $STRATUM_PORT_A, tag $PUBLIC_TAG"
start_gateway A "$STRATUM_PORT_A" "$API_PORT_A" ",
    \"coinbase_tag_secondary\": \"$PUBLIC_TAG\""

step "starting gateway B on stratum port $STRATUM_PORT_B, no tag"
start_gateway B "$STRATUM_PORT_B" "$API_PORT_B" ""

step "starting miners: alice on gateway A, bob on gateway B"
MINERS=()
start_miner() {
    local user=$1 cpus=$2 name=$3 port=$4
    taskset -c "$cpus" "$ROOT/target/release/sia-test-miner" \
        "127.0.0.1:$port" "$user" > "$WORK/miner-$name.log" 2>&1 &
    PIDS+=($!)
    MINERS+=($!)
}
start_miner "$ALICE.rig" "$ALICE_CPUS" alice "$STRATUM_PORT_A"
start_miner "$BOB.rig" "$BOB_CPUS" bob "$STRATUM_PORT_B"

LEDGER_DB="$WORK/pool/regtest.redb"
LEDGER="$WORK/pool/shares.txt"

step "accumulating $ALICE_SHARES shares from alice and $BOB_SHARES from bob (up to ${TIMEOUT}s)"
deadline=$((SECONDS + TIMEOUT))
started=$SECONDS
last_report=$SECONDS
enough_at=""
while [ "$SECONDS" -lt "$deadline" ]; do
    if [ $((SECONDS - last_report)) -ge 30 ]; then
        last_report=$SECONDS
        printf '  %4ds: alice %s/%s, bob %s/%s at height %s\n' \
            $((SECONDS - started)) "${alice_n:-0}" "$ALICE_SHARES" "${bob_n:-0}" "$BOB_SHARES" \
            "$(cli getblockcount 2>/dev/null || echo '?')"
    fi
    alice_n=$(grep -c "<- accepted .*; $ALICE" "$WORK/pool.log" 2>/dev/null || true)
    bob_n=$(grep -c "<- accepted .*; $BOB" "$WORK/pool.log" 2>/dev/null || true)
    # A coinbase pays bob the subsidy only if its template was built after a share of alice's
    # and a share of bob's were credited. On regtest nearly every share is a block, and a
    # template can be one share behind the ledger, so once the counts are met wait for two
    # more accepted shares before stopping the miners.
    if [ "$alice_n" -ge "$ALICE_SHARES" ] && [ "$bob_n" -ge "$BOB_SHARES" ]; then
        accepted_n=$(grep -c '<- accepted' "$WORK/pool.log" 2>/dev/null || true)
        [ -n "$enough_at" ] || enough_at=$((accepted_n + 2))
        [ "$accepted_n" -ge "$enough_at" ] && break
    fi
    sleep 2
done
printf '  alice %s, bob %s\n' "$alice_n" "$bob_n"
[ "$alice_n" -ge "$ALICE_SHARES" ] || fail "alice produced $alice_n shares in ${TIMEOUT}s, wanted $ALICE_SHARES"
[ "$bob_n" -ge "$BOB_SHARES" ] || fail "bob produced $bob_n shares in ${TIMEOUT}s, wanted $BOB_SHARES"

for pid in "${MINERS[@]}"; do kill "$pid" 2>/dev/null || true; done
sleep 2
kill "$POOL_PID" 2>/dev/null || true
sleep 2
"$ROOT/target/release/ratum-prime" --dump-ledger --ledger "$LEDGER_DB" > "$LEDGER" \
    || fail "could not dump the ledger $LEDGER_DB"

step "work credited per identity and tag"
awk '{ split($3, u, "."); key = u[1] " " ($5 == "" ? "(no tag)" : $5); work[key] += $2; count[key]++ }
     END { for (k in work) printf "  %-55s %3d shares %6d work\n", k, count[k], work[k] }' \
    "$LEDGER" | sort -k2

if grep " $ALICE\.\| $ALICE " "$LEDGER" | grep -qv " $PUBLIC_TAG\$"; then
    fail "a share of alice's does not carry the tag $PUBLIC_TAG gateway A was started with"
fi
if grep " $BOB\.\| $BOB " "$LEDGER" | grep -q " $PUBLIC_TAG\$"; then
    fail "a share of bob's carries the public tag; gateway B was started with none"
fi

step "each pooled coinbase pays the split with the fee and leaves the pool the remainder"
checked=0
subsidy_only=0
charged=0
subsidized=0
for h in $(seq "$((ACTIVATION_HEIGHT + 1))" "$(cli getblockcount)"); do
    hash=$(cli getblockhash "$h")
    block=$(cli getblock "$hash" 2)
    line=$(grep "<- accepted .*hash=$hash" "$WORK/pool.log" || true)
    [ -n "$line" ] || fail "the pool has no acceptance line for the block at height $h"
    split_sats=$(sed -n 's/.*split=\([0-9]*\).*/\1/p' <<<"$line")
    if [ "$split_sats" = 0 ]; then
        # Subsidy-only work: served between a tip change and the next coinbaser split, its
        # coinbase pays the pool alone and the pool records what it owes (README, Owed blocks).
        subsidy_only=$((subsidy_only + 1))
        continue
    fi
    paid=$(jq -r --arg a "$ALICE" --arg b "$BOB" --arg p "$POOL_ADDRESS" '
        .tx[0].vout[] | select(.scriptPubKey.address == $a or .scriptPubKey.address == $b
                               or .scriptPubKey.address == $p)
        | "\(.scriptPubKey.address) \((.value * 100000000) | round)"' <<<"$block")
    k=$(grep -n " $hash\( \|$\)" "$LEDGER" | cut -d: -f1)
    [ -n "$k" ] || fail "height $h: no ledger line records the share that solved $hash"
    value=$(jq -r '[.tx[0].vout[].value] | add | . * 100000000 | round' <<<"$block")
    matched=$(printf '%s\n' "$paid" | python3 "$WORK/match_split.py" "$LEDGER" "$((k - 1))" \
        "$value" "$MIN_PAYOUT" "$POOL_ADDRESS" "$PUBLIC_TAG" "$FEE_BPS" "$SUBSIDY_BPS" "$ALICE" "$BOB") \
        || fail "height $h pays [$(tr '\n' ';' <<<"$paid")], the split of no recent window with the fee"
    read -r prefix alice_sats alice_plain bob_sats bob_plain <<<"$matched"
    checked=$((checked + 1))
    [ "$alice_sats" -lt "$alice_plain" ] && charged=$((charged + 1))
    [ "$bob_sats" -gt "$bob_plain" ] && subsidized=$((subsidized + 1))
    printf '  height %-3s over %s shares: alice %s sats (%s without the fee), bob %s sats (%s without it)\n' \
        "$h" "$prefix" "$alice_sats" "$alice_plain" "$bob_sats" "$bob_plain"
done
[ "$checked" -ge 1 ] || fail "no pooled coinbase to check ($subsidy_only subsidy-only blocks)"
[ "$charged" -ge 1 ] \
    || fail "no coinbase paid alice less than her work earns; the public gateway fee was not charged"
[ "$subsidized" -ge 1 ] \
    || fail "no coinbase paid bob more than his own work earns; the fee work was not reassigned"

step "passed: $checked pooled coinbases match the split with the fee, $charged charged alice, $subsidized paid bob the fee work ($subsidy_only subsidy-only)"
printf 'ledger:\n'
cat "$LEDGER"
