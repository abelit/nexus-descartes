#!/usr/bin/env bash
# End-to-end governance check against real PostgreSQL and MySQL containers.
#
# Covers: login, connection setup, policy publish, policy denial over HTTP,
# multi-step/countersign approval, one-time execution token, audit chain
# verification, and the PostgreSQL audit sink.
#
# Usage: scripts/e2e-governance.sh [path-to-dbx-web]
# Requires: docker, curl, jq, uuidgen, a built dbx-web binary with
# `--features enterprise-audit`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${1:-$ROOT/target/debug/dbx-web}"
PORT="${DBX_E2E_PORT:-4317}"
PG_PORT="${DBX_E2E_PG_PORT:-55432}"
MYSQL_PORT="${DBX_E2E_MYSQL_PORT:-53306}"
BASE="http://127.0.0.1:$PORT"
WORK="$(mktemp -d /tmp/dbx-e2e-gov.XXXXXX)"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then kill "$SERVER_PID" 2>/dev/null || true; fi
  docker rm -f dbx-e2e-pg dbx-e2e-mysql >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; echo "--- server log ---" >&2; tail -40 "$WORK/server.log" >&2 || true; exit 1; }
pass() { echo "ok: $*"; }

wait_for() {
  local what="$1" attempts="$2"
  shift 2
  for _ in $(seq 1 "$attempts"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "timed out waiting for $what"
}

http() {
  local method="$1" path="$2" cookie="$3" body="${4:-}"
  local args=(-sS -o "$WORK/body.json" -w '%{http_code}' -b "$cookie" -c "$cookie" -X "$method" -H 'content-type: application/json')
  if [[ -n "$body" ]]; then args+=(-d "$body"); fi
  curl "${args[@]}" "$BASE$path"
}

expect_status() {
  local expected="$1" actual="$2" what="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "response body: $(cat "$WORK/body.json" 2>/dev/null || true)" >&2
    fail "$what: expected HTTP $expected, got $actual"
  fi
}

[[ -x "$BIN" ]] || { echo "missing binary: $BIN" >&2; exit 2; }

echo "starting containers"
docker run -d --rm --name dbx-e2e-pg -e POSTGRES_PASSWORD=dbx -e POSTGRES_DB=app -p "$PG_PORT:5432" postgres:16 >/dev/null
docker run -d --rm --name dbx-e2e-mysql -e MYSQL_ROOT_PASSWORD=dbx -e MYSQL_DATABASE=app -p "$MYSQL_PORT:3306" mysql:8.0.46 >/dev/null
wait_for postgres 90 docker exec dbx-e2e-pg pg_isready -U postgres
wait_for mysql 120 docker exec dbx-e2e-mysql mysqladmin ping -h127.0.0.1 -uroot -pdbx --silent

echo "starting dbx-web"
DBX_DATA_DIR="$WORK/data" \
DBX_PASSWORD=test \
DBX_PORT="$PORT" \
DBX_GOVERNANCE_MODE=enforce \
DBX_AUDIT_MODE=on \
DBX_AUDIT_EXPORT_POSTGRES_URL="postgres://postgres:dbx@127.0.0.1:$PG_PORT/app?sslmode=disable" \
DBX_AUDIT_EXPORT_POSTGRES_TABLE=dbx_audit_events \
"$BIN" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
wait_for "dbx-web" 60 curl -sf "$BASE/api/auth/check"

ADMIN="$WORK/admin.jar"
status=$(http POST /api/auth/login "$ADMIN" '{"email":"admin","password":"test"}')
expect_status 200 "$status" "admin login"
pass "admin login"

PG_ID="$(uuidgen)"
MYSQL_ID="$(uuidgen)"
status=$(http POST /api/connection/save "$ADMIN" "{\"configs\":[{\"id\":\"$PG_ID\",\"name\":\"e2e-pg\",\"db_type\":\"postgres\",\"host\":\"127.0.0.1\",\"port\":$PG_PORT,\"username\":\"postgres\",\"password\":\"dbx\",\"database\":\"app\"},{\"id\":\"$MYSQL_ID\",\"name\":\"e2e-mysql\",\"db_type\":\"mysql\",\"host\":\"127.0.0.1\",\"port\":$MYSQL_PORT,\"username\":\"root\",\"password\":\"dbx\",\"database\":\"app\"}]}")
expect_status 200 "$status" "save connections"
pass "saved PostgreSQL and MySQL connections"

status=$(http POST /api/query/execute "$ADMIN" "{\"connectionId\":\"$PG_ID\",\"database\":\"app\",\"sql\":\"select 1 as ok\"}")
expect_status 200 "$status" "postgres select"
status=$(http POST /api/query/execute "$ADMIN" "{\"connectionId\":\"$MYSQL_ID\",\"database\":\"app\",\"sql\":\"select 1 as ok\"}")
expect_status 200 "$status" "mysql select"
pass "executed SQL on both drivers"

status=$(http POST /api/policies "$ADMIN" '{"scope_type":"global","scope_id":"","note":"e2e","document":{"rules":[{"id":"e2e.ddl.approval","enabled":true,"priority":300,"action":"require_approval","message":"E2E DDL needs approval","match":{"statement_types":["ddl"]}}]}}')
expect_status 200 "$status" "publish policy"
pass "published DDL approval policy"

# Users: two approvers and one requester who is not an approver.
create_user() {
  local email="$1" name="$2" role="$3"
  local status
  status=$(http POST /api/users "$ADMIN" "{\"email\":\"$email\",\"display_name\":\"$name\",\"password\":\"password123\",\"role\":\"$role\"}")
  expect_status 200 "$status" "create user $email"
  jq -r '.id' "$WORK/body.json"
}
DBA1_ID=$(create_user dba1@example.com "DBA One" dba)
DBA2_ID=$(create_user dba2@example.com "DBA Two" dba)
REQ_ID=$(create_user requester@example.com "Requester" operator)
[[ "$DBA1_ID" != "null" && "$DBA2_ID" != "null" && "$REQ_ID" != "null" ]] || fail "create users"
pass "created two DBA approvers and one operator requester"

status=$(http POST /api/approval-templates "$ADMIN" "{\"name\":\"e2e-two-step\",\"scope_type\":\"global\",\"scope_id\":\"\",\"steps\":{\"steps\":[{\"mode\":\"any\",\"roles\":[\"dba\"],\"users\":[]},{\"mode\":\"all\",\"roles\":[],\"users\":[\"$DBA1_ID\",\"$DBA2_ID\"]}]}}")
expect_status 200 "$status" "publish template"
pass "published two-step template (any DBA, then countersign)"

DBA1="$WORK/dba1.jar"
DBA2="$WORK/dba2.jar"
REQ="$WORK/requester.jar"
for pair in "dba1@example.com:$DBA1" "dba2@example.com:$DBA2" "requester@example.com:$REQ"; do
  email="${pair%%:*}"
  jar="${pair##*:}"
  status=$(http POST /api/auth/login "$jar" "{\"email\":\"$email\",\"password\":\"password123\"}")
  expect_status 200 "$status" "login $email"
done
pass "approver and requester sessions"

PG_DDL="create table e2e_pg(id int)"
status=$(http POST /api/query/execute "$REQ" "{\"connectionId\":\"$PG_ID\",\"database\":\"app\",\"sql\":\"$PG_DDL\"}")
expect_status 403 "$status" "postgres DDL without approval"
grep -q "POLICY_APPROVAL_REQUIRED" "$WORK/body.json" || fail "postgres DDL denial did not mention approval"
pass "postgres DDL denied with 403 before approval"

MYSQL_DDL="create table e2e_mysql(id int)"
status=$(http POST /api/query/execute "$REQ" "{\"connectionId\":\"$MYSQL_ID\",\"database\":\"app\",\"sql\":\"$MYSQL_DDL\"}")
expect_status 403 "$status" "mysql DDL without approval"
pass "mysql DDL denied with 403 before approval"

status=$(http POST /api/approvals "$REQ" "{\"connection_id\":\"$PG_ID\",\"database\":\"app\",\"sql\":\"$PG_DDL\",\"justification\":\"e2e\"}")
expect_status 200 "$status" "create approval"
APPROVAL_ID=$(jq -r '.id' "$WORK/body.json")
[[ "$(jq -r '.step_count' "$WORK/body.json")" == "2" ]] || fail "approval did not use the two-step template"
pass "approval created with two steps"

# The requester cannot decide their own request.
status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$REQ" '{"comment":"self"}')
expect_status 403 "$status" "self approval"
pass "requester cannot approve their own request"

# A DBA created after the request opened is not in the creation snapshot and
# cannot vote, even though the step names the `dba` role.
DBA3_ID=$(create_user dba3@example.com "DBA Late" dba)
DBA3="$WORK/dba3.jar"
status=$(http POST /api/auth/login "$DBA3" '{"email":"dba3@example.com","password":"password123"}')
expect_status 200 "$status" "login dba3"
status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$DBA3" '{"comment":"late"}')
expect_status 403 "$status" "late approver vote"
pass "a DBA granted after creation cannot join the in-flight approval"

status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$DBA1" '{"comment":"step one"}')
expect_status 200 "$status" "first step approval"
[[ "$(jq -r '.status' "$WORK/body.json")" == "pending" ]] || fail "request should stay pending after step one"
[[ "$(jq -r '.current_step_no' "$WORK/body.json")" == "2" ]] || fail "current step should advance to 2"
pass "any-step approved and advanced to the countersign step"

# The first countersigner is not enough, and a second vote on the same step by
# the same approver is refused.
status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$DBA1" '{"comment":"step two"}')
expect_status 200 "$status" "first countersign vote"
[[ "$(jq -r '.status' "$WORK/body.json")" == "pending" ]] || fail "one of two countersigners must not approve"
status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$DBA1" '{"comment":"again"}')
expect_status 409 "$status" "duplicate countersign vote"
status=$(http POST "/api/approvals/$APPROVAL_ID/approve" "$DBA2" '{"comment":"step two"}')
expect_status 200 "$status" "second countersign vote"
[[ "$(jq -r '.status' "$WORK/body.json")" == "approved" ]] || fail "request should be approved after countersign"
pass "countersign completed and request approved"

status=$(http GET "/api/approvals/$APPROVAL_ID" "$REQ")
expect_status 200 "$status" "approval detail"
[[ "$(jq -r '.decisions | length' "$WORK/body.json")" == "3" ]] || fail "expected three recorded votes"
pass "approval timeline exposes recorded votes"

status=$(http POST "/api/approvals/$APPROVAL_ID/execute-token" "$REQ")
expect_status 200 "$status" "issue token"
TOKEN=$(jq -r '.token' "$WORK/body.json")
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || fail "empty execution token"
pass "issued one-time execution token"

status=$(curl -sS -o "$WORK/body.json" -w '%{http_code}' -b "$REQ" -X POST -H 'content-type: application/json' \
  -H "X-DBX-Approval-Token: $TOKEN" \
  -d "{\"connectionId\":\"$PG_ID\",\"database\":\"app\",\"sql\":\"$PG_DDL\"}" "$BASE/api/query/execute")
expect_status 200 "$status" "approved DDL execution"
pass "approved PostgreSQL DDL executed with the token"

status=$(http POST /api/query/execute "$REQ" "{\"connectionId\":\"$PG_ID\",\"database\":\"app\",\"sql\":\"$PG_DDL\"}")
expect_status 403 "$status" "token reuse / new execution"
pass "a spent token cannot authorize another execution"

# MySQL takes the same multi-step path.
status=$(http POST /api/approvals "$REQ" "{\"connection_id\":\"$MYSQL_ID\",\"database\":\"app\",\"sql\":\"$MYSQL_DDL\",\"justification\":\"e2e\"}")
expect_status 200 "$status" "create mysql approval"
MYSQL_APPROVAL=$(jq -r '.id' "$WORK/body.json")
http POST "/api/approvals/$MYSQL_APPROVAL/approve" "$DBA1" '{"comment":"ok"}' >/dev/null
http POST "/api/approvals/$MYSQL_APPROVAL/approve" "$DBA1" '{"comment":"ok"}' >/dev/null
http POST "/api/approvals/$MYSQL_APPROVAL/approve" "$DBA2" '{"comment":"ok"}' >/dev/null
status=$(http POST "/api/approvals/$MYSQL_APPROVAL/execute-token" "$REQ")
expect_status 200 "$status" "mysql token"
MYSQL_TOKEN=$(jq -r '.token' "$WORK/body.json")
status=$(curl -sS -o "$WORK/body.json" -w '%{http_code}' -b "$REQ" -X POST -H 'content-type: application/json' \
  -H "X-DBX-Approval-Token: $MYSQL_TOKEN" \
  -d "{\"connectionId\":\"$MYSQL_ID\",\"database\":\"app\",\"sql\":\"$MYSQL_DDL\"}" "$BASE/api/query/execute")
expect_status 200 "$status" "mysql approved DDL"
pass "approved MySQL DDL executed with the token"

# Audit chain and records.
status=$(http GET "/api/audit/verify" "$ADMIN")
expect_status 200 "$status" "audit verify"
[[ "$(jq -r '.first_broken_seq' "$WORK/body.json")" == "null" ]] || fail "audit chain is broken"

found_required=0
for _ in $(seq 1 20); do
  http GET "/api/audit/events?limit=200" "$ADMIN" >/dev/null
  if jq -e '.events | any(.decision == "approval_required")' "$WORK/body.json" >/dev/null 2>&1; then
    found_required=1
    break
  fi
  sleep 1
done
[[ "$found_required" == "1" ]] || fail "no approval_required audit event found"
jq -e '.events | any(.decision == "allowed" and .outcome == "success")' "$WORK/body.json" >/dev/null || fail "no allowed execution event found"
pass "audit records approval_required decisions and the allowed execution"

# PostgreSQL export sink.
exported=0
for _ in $(seq 1 40); do
  count=$(docker exec dbx-e2e-pg psql -U postgres -d app -tAc \
    "select count(*) from dbx_audit_events where body->>'sql_text' like '%e2e_pg%'" 2>/dev/null || echo 0)
  if [[ "${count:-0}" -ge 1 ]]; then exported=1; break; fi
  sleep 1
done
[[ "$exported" == "1" ]] || fail "PostgreSQL audit sink did not receive the DDL event"
pass "PostgreSQL audit sink stored the signed event"

echo "E2E PASSED"
