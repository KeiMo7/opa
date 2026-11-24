#!/usr/bin/env bash
# End-to-end exercise of the tamper-evident decision ledger:
#   1. boot a real OPA server with the ledger_logger plugin
#   2. drive decisions over HTTP
#   3. verify the ledger offline (human + machine output)
#   4. tamper one byte / delete a segment / reorder two records
set -u
OPA=/home/wll/uid82/.tmp/opa
WORK=/home/wll/uid82/.tmp/e2e-data
REPORT=/home/wll/uid82/reports/e2e-cli.txt
rm -rf "$WORK"
mkdir -p "$WORK/ledger"
cd "$WORK"

cat > policy.rego <<'EOF'
package example

default allow := false

allow if {
	input.user == "alice"
}
EOF

cat > config.yaml <<EOF
plugins:
  ledger_logger:
    directory: $WORK/ledger
    max_records_per_segment: 3
    max_segment_size_mb: 1
    disk_limit_mb: 16
decision_logs:
  plugin: ledger_logger
  console: false
EOF

{
echo "================ 1. boot OPA server ================"
"$OPA" run --server --addr localhost:8191 -c config.yaml policy.rego > server.log 2>&1 &
OPA_PID=$!
echo "opa pid=$OPA_PID"

for i in $(seq 1 50); do
  if curl -sf localhost:8191/health >/dev/null 2>&1; then break; fi
  sleep 0.2
done
curl -s localhost:8191/health; echo

echo "================ 2. drive 7 decisions ================"
for i in 0 1 2 3 4 5 6; do
  USER=alice
  [ $((i % 2)) -eq 1 ] && USER=bob
  curl -s -X POST localhost:8191/v1/data/example/allow \
    -H 'Content-Type: application/json' \
    -d "{\"input\":{\"user\":\"$USER\",\"secret\":\"sensitive-value-$i\"}}" >/dev/null
done
sleep 1
kill "$OPA_PID" 2>/dev/null
wait "$OPA_PID" 2>/dev/null
echo "server stopped"

echo "================ ledger files on disk ================"
ls -la ledger/
echo "---- secret leak check ----"
grep -l "sensitive-value" ledger/* && echo "LEAK!" || echo "OK: no raw sensitive input on disk"

echo "================ 3. offline verify (clean) ================"
"$OPA" ledger verify ledger --key ledger/ledger.key -o report.json
echo "verify exit=$? (want 0)"
echo "---- machine report ----"
cat report.json

echo
echo "================ 4a. tamper one byte ================"
SEG=$(ls ledger/segment-*.jsonl | head -1)
cp -a "$SEG" "$SEG.bak"
python3 - <<PY
p = "$SEG"
data = open(p, "rb").read()
idx = data.find(b"decision_id")
b = bytearray(data)
b[idx+15] = ord('X') if b[idx+15] != ord('X') else ord('Y')
open(p, "wb").write(bytes(b))
PY
"$OPA" ledger verify ledger --key ledger/ledger.key; echo "verify exit=$? (want non-zero)"
mv "$SEG.bak" "$SEG"
"$OPA" ledger verify ledger --key ledger/ledger.key >/dev/null; echo "restored verify exit=$? (want 0)"

echo "================ 4b. reorder two records ================"
SEG=$(ls ledger/segment-*.jsonl | head -1)
cp -a "$SEG" "$SEG.bak"
python3 - <<PY
p = "$SEG"
lines = open(p, "rb").read().splitlines(keepends=True)
if len(lines) >= 3:
    lines[1], lines[2] = lines[2], lines[1]
open(p, "wb").write(b"".join(lines))
PY
"$OPA" ledger verify ledger --key ledger/ledger.key; echo "verify exit=$? (want non-zero)"
mv "$SEG.bak" "$SEG"
"$OPA" ledger verify ledger --key ledger/ledger.key >/dev/null; echo "restored verify exit=$? (want 0)"

echo "================ 4c. delete an interior segment ================"
mapfile -t ALL < <(ls ledger/segment-*.jsonl)
if [ "${#ALL[@]}" -ge 3 ]; then
  cp -a "${ALL[1]}" "${ALL[1]}.bak"
  rm "${ALL[1]}"
  "$OPA" ledger verify ledger --key ledger/ledger.key; echo "verify exit=$? (want non-zero: chain broken)"
  mv "${ALL[1]}.bak" "${ALL[1]}"
  "$OPA" ledger verify ledger --key ledger/ledger.key >/dev/null; echo "restored verify exit=$? (want 0)"
else
  echo "not enough segments to test deletion (got ${#ALL[@]})"
fi

echo "================ 5. foreign key rejected ================"
mkdir -p ledgerB
"$OPA" ledger verify ledgerB 2>&1 | head -2 || true

echo "================ ALL E2E STEPS DONE ================"
} 2>&1 | tee "$REPORT"
