#!/bin/bash
set -uo pipefail

# security/self_dev/dev_approval_pre_push_hook.sh -- OPTIONAL, OPT-IN
# per-clone git `pre-push` hook implementing integration option 2 of
# the three surveyed (and none implemented) in ARCHITECTURE.md's
# "WAIO Self-Development Engine Human Approval Gate" phase, Section 5:
# a local git hook that blocks a push to a protected branch unless a
# corresponding APPROVED record already exists for the exact commit
# being pushed.
#
# NOT installed by this file's mere presence in the repository. A
# human opts in, per clone, by copying or symlinking this file to
# `.git/hooks/pre-push` and making it executable -- e.g.:
#   cp security/self_dev/dev_approval_pre_push_hook.sh .git/hooks/pre-push
#   chmod +x .git/hooks/pre-push
# Nothing in this repository does that automatically. This is
# convenient for a human operator; it is explicitly NOT a substitute
# for a centrally-enforced check (a hook is per-clone, not enforced for
# anyone else, and can be removed or bypassed with `git push
# --no-verify` by anyone with write access to their own clone) -- see
# ARCHITECTURE.md's own Section 5 for why a CI required-check job
# (integration option 2, not this file) is the only centrally-enforced
# option of the three.
#
# WHAT THIS DOES: reads git's own pre-push hook protocol from stdin
# (lines of "<local ref> <local sha1> <remote ref> <remote sha1>"). For
# any line whose remote ref resolves to a branch in
# dev_approval_lib.PROTECTED_TARGET_BRANCHES (today: master, develop),
# requires WAIO_SELF_DEV_PUSH_APPROVAL_ID to name an existing record
# that is effective_status == APPROVED, whose own record.target_branch
# matches that branch, and whose own record.head_ref matches the
# EXACT local_sha1 being pushed -- an approval for one commit can never
# be reused to wave through a different one. Any other branch is
# allowed through unconditionally, zero friction.
#
# WHAT THIS NEVER DOES: never runs `git push`, `git merge`, `gh pr
# merge`, or anything else -- it only reads this gate's own existing
# `status` verb (which itself only reads a JSON record from disk) and
# exits 0 (let git's own push proceed) or non-zero (git aborts the
# push itself, before anything leaves this machine). Identical
# "governs, never executes" posture as dev_approval_gate.sh itself.

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || REPO_ROOT="$(pwd)"
GATE="${WAIO_SELF_DEV_GATE:-$REPO_ROOT/security/self_dev/dev_approval_gate.sh}"

_sdph_status_fields() {
  # _sdph_status_fields STATUS_JSON -- prints exactly three lines:
  # effective_status, record.target_branch, record.head_ref (empty
  # line for any that is absent or not a string). Explicit dict .get()
  # chain only -- deliberately no eval of any field value, same "never
  # eval a value read from a record" discipline as
  # dev_approval_gate.sh's own D3/D5 structural guards.
  python3 -c "
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    d = {}
record = d.get('record') if isinstance(d.get('record'), dict) else {}
def s(v):
    return v if isinstance(v, str) else ''
print(s(d.get('effective_status')))
print(s(record.get('target_branch')))
print(s(record.get('head_ref')))
" "$1" 2>/dev/null
}

_sdph_protected_branches() {
  python3 -c "
import os, sys
sys.path.insert(0, os.path.join('$REPO_ROOT', 'security', 'self_dev'))
import dev_approval_lib as dal
print(' '.join(sorted(dal.PROTECTED_TARGET_BRANCHES)))
"
}

main() {
  local blocked=0
  local protected; protected="$(_sdph_protected_branches)" || protected="master develop"

  while read -r local_ref local_sha remote_ref remote_sha; do
    [ -z "${local_ref:-}" ] && continue
    local branch="${remote_ref#refs/heads/}"

    local is_protected=0
    for b in $protected; do
      [ "$branch" = "$b" ] && is_protected=1 && break
    done
    [ "$is_protected" -eq 0 ] && continue

    echo "[pre-push] '$branch' is a protected target branch -- checking for a human-approved self-development record..." >&2

    local approval_id="${WAIO_SELF_DEV_PUSH_APPROVAL_ID:-}"
    if [ -z "$approval_id" ]; then
      echo "[pre-push] BLOCKED: pushing to '$branch' requires WAIO_SELF_DEV_PUSH_APPROVAL_ID set to an APPROVED self-development approval id." >&2
      echo "[pre-push]   1. $GATE propose <operation> $branch $local_sha <your-identity> [--path ...]" >&2
      echo "[pre-push]   2. a human (separately, by hand): $GATE approve <approval_id> <approver-identity> \"<reason>\"" >&2
      echo "[pre-push]   3. WAIO_SELF_DEV_PUSH_APPROVAL_ID=<approval_id> git push ..." >&2
      blocked=1
      continue
    fi

    local out rc
    out="$("$GATE" status "$approval_id" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
      echo "[pre-push] BLOCKED: status lookup for approval id '$approval_id' failed (exit $rc): $out" >&2
      blocked=1
      continue
    fi

    local fields effective_status record_target_branch record_head_ref
    fields="$(_sdph_status_fields "$out")"
    effective_status="$(sed -n '1p' <<<"$fields")"
    record_target_branch="$(sed -n '2p' <<<"$fields")"
    record_head_ref="$(sed -n '3p' <<<"$fields")"

    if [ "$effective_status" != "APPROVED" ]; then
      echo "[pre-push] BLOCKED: approval id '$approval_id' is '$effective_status', not APPROVED." >&2
      blocked=1
      continue
    fi
    if [ "$record_target_branch" != "$branch" ]; then
      echo "[pre-push] BLOCKED: approval id '$approval_id' was approved for target_branch '$record_target_branch', not '$branch' -- refusing to reuse it for a different branch." >&2
      blocked=1
      continue
    fi
    if [ "$record_head_ref" != "$local_sha" ]; then
      echo "[pre-push] BLOCKED: approval id '$approval_id' was approved for commit '$record_head_ref', not the commit being pushed ('$local_sha') -- refusing to reuse an approval for a different commit." >&2
      blocked=1
      continue
    fi

    echo "[pre-push] OK: approval id '$approval_id' is APPROVED for exactly this commit ('$local_sha') on '$branch'." >&2
  done

  [ "$blocked" -eq 0 ]
}

main
