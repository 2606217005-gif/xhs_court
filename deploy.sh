#!/usr/bin/env bash
set -euo pipefail

# XHS Court - Vercel deployment helper
# Usage:
#   1) Create a token at https://vercel.com/account/tokens
#   2) export VERCEL_TOKEN=your_token_here
#   3) ./deploy.sh
# The script sets VERCEL_ORG_ID and VERCEL_PROJECT_ID from .vercel/project.json if not already set.

log() { echo "[deploy] $*"; }

# Ensure vercel CLI exists
if ! command -v vercel >/dev/null 2>&1; then
  log "Vercel CLI not found. Install with: npm i -g vercel"
  exit 1
fi

# Read org/project IDs from .vercel/project.json if not provided
if [[ -z "${VERCEL_ORG_ID:-}" || -z "${VERCEL_PROJECT_ID:-}" ]]; then
  if [[ -f ".vercel/project.json" ]]; then
    # Prefer Python to parse JSON to avoid jq dependency
    eval "$(python3 - <<'PY'
import json, sys
try:
    with open('.vercel/project.json') as f:
        d = json.load(f)
    org = d.get('orgId', '')
    proj = d.get('projectId', '')
    if org:
        print(f'export VERCEL_ORG_ID={org}')
    if proj:
        print(f'export VERCEL_PROJECT_ID={proj}')
except Exception as e:
    print(f"echo 'Failed to parse .vercel/project.json: {e}'", file=sys.stderr)
PY
    )"
  fi
fi

# Fallback hardcoded IDs if parsing failed (safe: these are public identifiers, not secrets)
export VERCEL_ORG_ID="${VERCEL_ORG_ID:-team_cmPkfBpmtz3UDSiMYUcnB52B}"
export VERCEL_PROJECT_ID="${VERCEL_PROJECT_ID:-prj_TBXubZdm6ZTxZAPXFMxISBqvHI6m}"

# Check token
if [[ -z "${VERCEL_TOKEN:-}" ]]; then
  log "Missing VERCEL_TOKEN. Create at https://vercel.com/account/tokens and export VERCEL_TOKEN before running."
  exit 2
fi

log "Using org=$VERCEL_ORG_ID project=$VERCEL_PROJECT_ID"
log "Vercel CLI version: $(vercel --version || true)"

# Deploy non-interactively
log "Deploying (prod, non-interactive)..."
set +e
DEPLOY_OUTPUT=$(vercel deploy --prod --yes --token "$VERCEL_TOKEN" 2>&1)
DEPLOY_EXIT=$?
set -e

echo "$DEPLOY_OUTPUT"
if [[ $DEPLOY_EXIT -ne 0 ]]; then
  log "Deploy failed (exit $DEPLOY_EXIT). Common fixes:"
  log " - Check your network/TLS/代理设置，尝试更换网络或关闭系统代理"
  log " - 确认 VERCEL_TOKEN 有效且未过期"
  log " - 如需交互登录：运行 vercel login 后再重试"
  exit $DEPLOY_EXIT
fi

log "Deploy command completed. If a URL is shown above, open it."
log "Post-deploy checks: visit /__health and /__diag on your deployment domain."
log "Example: https://<your-domain>/__health and https://<your-domain>/__diag"

log "Ensure runtime env vars are configured in Vercel dashboard:"
log " - SECRET_KEY (required)"
log " - DATABASE_URL (recommended: Postgres/Supabase)"
log " - SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_BUCKET (if using Supabase storage)"
log " - Optional: DOUBAO_API_URL, DOUBAO_API_KEY, DOUBAO_MODEL, DOUBAO_MAX_COMPLETION_TOKENS"