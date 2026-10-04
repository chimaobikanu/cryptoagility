#!/usr/bin/env bash
# Publish CryptoAgility to GitHub from a clean export of the current tree.
#
#   GITHUB_TOKEN=xxx ./scripts/publish_github.sh              # private (default)
#   GITHUB_TOKEN=xxx ./scripts/publish_github.sh --public     # public
#   GITHUB_TOKEN=xxx ./scripts/publish_github.sh --repo other --owner someone
#
# The token is read from the environment and is never echoed, never written to
# .git/config, and never passed as a command-line argument.
#
# Deliberately pushes a single clean commit from an export of the working tree,
# so internal documents that were once tracked are not carried into history.
set -euo pipefail

REPO="cryptoagility"
VISIBILITY="private"
OWNER=""
DESCRIPTION="Cryptographic asset discovery and post-quantum migration register. Finds cryptography in source, config, certificates and live TLS connections. Runs offline."
TOPICS='["cryptography","post-quantum","pqc","cbom","cyclonedx","security-tools","compliance"]'

while [ $# -gt 0 ]; do
  case "$1" in
    --public)  VISIBILITY="public"; shift ;;
    --private) VISIBILITY="private"; shift ;;
    --repo)    REPO="$2"; shift 2 ;;
    --owner)   OWNER="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "error: GITHUB_TOKEN is not set." >&2
  echo "Add it in hPanel -> Hermes Agent -> Dashboard -> Environment, then re-run." >&2
  exit 1
fi

cd "$(dirname "$0")/.."
ROOT="$PWD"

api() {  # api METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
      -d "$body" "https://api.github.com$path"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" \
      "https://api.github.com$path"
  fi
}

echo "1/6  verifying token"
ME=$(api GET /user)
LOGIN=$(printf '%s' "$ME" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("login",""))' 2>/dev/null || true)
if [ -z "$LOGIN" ]; then
  echo "error: token rejected by GitHub." >&2
  printf '%s\n' "$ME" | head -5 >&2
  exit 1
fi
[ -z "$OWNER" ] && OWNER="$LOGIN"
echo "     authenticated as: $LOGIN  (repo owner: $OWNER)"

echo "2/6  checking whether $OWNER/$REPO already exists"
CODE=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GITHUB_TOKEN" \
  "https://api.github.com/repos/$OWNER/$REPO")
if [ "$CODE" = "200" ]; then
  CONTENT=$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/$OWNER/$REPO/contents")
  if [ "$CONTENT" != "404" ]; then
    echo "error: $OWNER/$REPO exists and already has content. Use --repo for a different name." >&2
    exit 1
  fi
  echo "     already exists and is empty — will push into it"
  EXISTING=1
else
  echo "     name is free"
  EXISTING=0
fi

if [ "${EXISTING:-0}" = "1" ]; then
  echo "3/6  reusing the existing empty repository"
  FULL="$OWNER/$REPO"
else
echo "3/6  creating $VISIBILITY repository"
CREATED=$(api POST /user/repos "$(python3 - "$REPO" "$VISIBILITY" "$DESCRIPTION" <<'PY'
import json, sys
name, vis, desc = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "name": name,
    "description": desc,
    "private": vis == "private",
    "has_issues": True,
    "has_wiki": False,
    "has_projects": False,
    "auto_init": False,
}))
PY
)")
FULL=$(printf '%s' "$CREATED" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("full_name",""))' 2>/dev/null || true)
if [ -z "$FULL" ]; then
  echo "error: repository creation failed." >&2
  printf '%s\n' "$CREATED" | head -10 >&2
  exit 1
fi
echo "     created: $FULL"
fi

echo "4/6  setting topics"
api PUT "/repos/$FULL/topics" "{\"names\": $TOPICS}" >/dev/null && echo "     topics set"

echo "5/6  exporting a clean tree and pushing"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git archive HEAD | tar -x -C "$WORK"
[ -f "$WORK/.gitignore" ] || { echo "error: export looks wrong" >&2; exit 1; }
[ -f "$WORK/cryptoagility.py" ] || { echo "error: export is missing the discovery core" >&2; exit 1; }

(
  cd "$WORK"
  git init -q -b main
  git add -A
  git -c user.email="c.kanu@mainnoltd.com" -c user.name="Maobyte Innovations Ltd" \
      commit -q -m "CryptoAgility 0.1.0 — cryptographic discovery and CBOM generation

Static discovery across Python, JavaScript, Java and Go, X.509 certificate
inspection, and runtime observation of negotiated TLS cryptography. CycloneDX
1.6 CBOM output and a prioritised migration report. Runs offline.

Open core under AGPL-3.0-or-later; migration orchestration is commercial."
  AUTH=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 | tr -d '\n')
  git -c http.extraheader="Authorization: Basic $AUTH" \
      push -q "https://github.com/$FULL.git" main
)

echo "6/6  verifying"
VERIFY=$(api GET "/repos/$FULL/contents/README.md")
printf '%s' "$VERIFY" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("path")=="README.md" else 1)' \
  && echo "     README present in the remote" \
  || { echo "error: remote verification failed" >&2; exit 1; }
api GET "/repos/$FULL/contents/LICENSE" >/dev/null && echo "     LICENSE present in the remote"

cat <<EOF

Done.
  Repository: https://github.com/$FULL
  Visibility: $VISIBILITY
  Next:       enable private vulnerability reporting under Settings > Security
              (SECURITY.md expects it), and confirm the CI workflow runs green.

EOF
if [ "$VISIBILITY" = "private" ]; then
  cat <<EOF
This is a private repository. Nothing is public yet. When you are ready:
  curl -X PATCH -H "Authorization: Bearer \$GITHUB_TOKEN" \\
       -H "Accept: application/vnd.github+json" \\
       -d '{"private":false}' https://api.github.com/repos/$FULL
EOF
fi
