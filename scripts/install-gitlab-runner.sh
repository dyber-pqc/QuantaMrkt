#!/usr/bin/env bash
#
# Install + register a GitLab Runner for the QuantaMrkt project against a
# self-hosted GitLab instance with a self-signed cert.
#
# Run as root (or with sudo) on a Debian/Ubuntu box that has network reach to
# the GitLab server. The same box that hosts GitLab is fine — runner workloads
# are isolated in Docker containers.
#
# Required:
#   REG_TOKEN     — runner authentication token from GitLab UI
#                   (Settings → CI/CD → Runners → New project runner → submit,
#                   then copy the `glrt-…` token shown.)
# Optional:
#   GITLAB_URL    — default https://192.168.0.220
#   RUNNER_TAGS   — default "quantamrkt,pqc"
#   RUNNER_NAME   — default "quantamrkt-docker-runner"
#   DEFAULT_IMAGE — default "python:3.12-slim-bookworm" (matches .gitlab-ci.yml)
#   CONCURRENT    — default 2  (max simultaneous jobs)
#   SKIP_TLS      — set to 1 to skip TLS verification entirely (insecure;
#                   only use as a last resort if cert fetch fails)
#
# Example:
#   sudo REG_TOKEN=glrt-XXXXXXXXXXXXXXXXXXXX ./install-gitlab-runner.sh
#
# Idempotent: safe to re-run. Existing registrations with the same name are
# replaced.

set -euo pipefail

GITLAB_URL="${GITLAB_URL:-https://192.168.0.220}"
RUNNER_TAGS="${RUNNER_TAGS:-quantamrkt,pqc}"
RUNNER_NAME="${RUNNER_NAME:-quantamrkt-docker-runner}"
DEFAULT_IMAGE="${DEFAULT_IMAGE:-python:3.12-slim-bookworm}"
CONCURRENT="${CONCURRENT:-2}"
SKIP_TLS="${SKIP_TLS:-0}"

log() { printf '\033[1;36m[runner-install]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[runner-install ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "Run as root (use sudo)."
[[ -n "${REG_TOKEN:-}" ]] || err "REG_TOKEN is required. Get it from GitLab → Settings → CI/CD → Runners → New project runner."

# Extract host[:port] from the URL for cert fetching
GITLAB_HOST=$(echo "$GITLAB_URL" | sed -E 's#^https?://##; s#/.*##')
GITLAB_HOSTNAME=$(echo "$GITLAB_HOST" | cut -d: -f1)
GITLAB_PORT=$(echo "$GITLAB_HOST" | grep -q ':' && echo "$GITLAB_HOST" | cut -d: -f2 || echo 443)

log "GitLab URL : $GITLAB_URL"
log "Host:port  : $GITLAB_HOSTNAME:$GITLAB_PORT"
log "Runner tags: $RUNNER_TAGS"

# ---------------------------------------------------------------------------
# 1. Install Docker if missing
# ---------------------------------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io
  systemctl enable --now docker
  log "Docker installed: $(docker --version)"
else
  log "Docker present: $(docker --version)"
fi

# ---------------------------------------------------------------------------
# 2. Install gitlab-runner if missing
# ---------------------------------------------------------------------------
if ! command -v gitlab-runner >/dev/null 2>&1; then
  log "Installing gitlab-runner from official apt repo..."
  curl -fsSL https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh \
    | bash
  apt-get install -y -qq gitlab-runner
  log "gitlab-runner installed: $(gitlab-runner --version | head -1)"
else
  log "gitlab-runner present: $(gitlab-runner --version | head -1)"
fi

# ---------------------------------------------------------------------------
# 3. Fetch GitLab TLS cert and install in runner trust store
# ---------------------------------------------------------------------------
CERT_DIR="/etc/gitlab-runner/certs"
mkdir -p "$CERT_DIR"
CERT_FILE="$CERT_DIR/${GITLAB_HOSTNAME}.crt"

if [[ "$SKIP_TLS" == "1" ]]; then
  log "SKIP_TLS=1 — registering without certificate verification"
  TLS_REG_FLAGS="--tls-ca-file= --skip-verify"  # informal placeholder; see env below
else
  log "Fetching TLS cert from $GITLAB_HOSTNAME:$GITLAB_PORT..."
  if echo | openssl s_client -showcerts -connect "$GITLAB_HOSTNAME:$GITLAB_PORT" \
        -servername "$GITLAB_HOSTNAME" 2>/dev/null \
      | openssl x509 -outform PEM > "$CERT_FILE" 2>/dev/null \
      && [[ -s "$CERT_FILE" ]]; then
    chmod 644 "$CERT_FILE"
    log "Cert saved to $CERT_FILE ($(wc -c < "$CERT_FILE") bytes)"
  else
    err "Could not fetch cert. Set SKIP_TLS=1 to bypass, or copy the cert manually to $CERT_FILE and re-run."
  fi
fi

# ---------------------------------------------------------------------------
# 4. Un-register any previous runner with the same name (idempotent re-run)
# ---------------------------------------------------------------------------
if gitlab-runner list 2>&1 | grep -q "^${RUNNER_NAME}"; then
  log "Unregistering existing runner '$RUNNER_NAME'..."
  gitlab-runner unregister --name "$RUNNER_NAME" || true
fi

# ---------------------------------------------------------------------------
# 5. Register the runner
# ---------------------------------------------------------------------------
log "Registering runner with $GITLAB_URL..."

REGISTER_ARGS=(
  --non-interactive
  --url "$GITLAB_URL"
  --token "$REG_TOKEN"
  --name "$RUNNER_NAME"
  --executor docker
  --docker-image "$DEFAULT_IMAGE"
  --docker-privileged=false
  --docker-volumes "/cache"
  --docker-pull-policy "if-not-present"
)

if [[ "$SKIP_TLS" == "1" ]]; then
  # Disable TLS verification for the runner→GitLab connection
  REGISTER_ARGS+=(--tls-ca-file "")
  export CI_SERVER_TLS_CA_FILE=""
  export GIT_SSL_NO_VERIFY=true
else
  REGISTER_ARGS+=(--tls-ca-file "$CERT_FILE")
fi

gitlab-runner register "${REGISTER_ARGS[@]}"

# ---------------------------------------------------------------------------
# 6. Set global concurrency and ensure service is running
# ---------------------------------------------------------------------------
log "Setting concurrent=$CONCURRENT..."
sed -i -E "s/^concurrent\s*=.*/concurrent = $CONCURRENT/" /etc/gitlab-runner/config.toml
grep -q "^concurrent" /etc/gitlab-runner/config.toml || \
  sed -i "1iconcurrent = $CONCURRENT" /etc/gitlab-runner/config.toml

systemctl enable gitlab-runner
systemctl restart gitlab-runner
sleep 2

# ---------------------------------------------------------------------------
# 7. Verify
# ---------------------------------------------------------------------------
log "Runner status:"
systemctl --no-pager status gitlab-runner | head -5 || true
echo
log "Registered runners:"
gitlab-runner list || true
echo
log "Verifying connection to GitLab..."
if gitlab-runner verify 2>&1 | tee /tmp/runner-verify.log | grep -q "is alive"; then
  log "✓ Runner is alive and connected to $GITLAB_URL"
else
  cat /tmp/runner-verify.log
  err "Runner verify failed. Check the log above. Common causes: bad REG_TOKEN, network reachability, TLS cert mismatch (try SKIP_TLS=1)."
fi

cat <<EOF

──────────────────────────────────────────────────────────────────
 Runner '$RUNNER_NAME' is registered and online.

 Next steps:
   1. In GitLab → Build → Pipeline schedules → ▶ play
      Run "HF sync (hourly)" first as a smoke test.
   2. Then run "PQC sign (every 6 hours)" — first run builds liboqs
      (~4 min); subsequent runs hit the cache (~30s).

 Useful commands:
   systemctl status gitlab-runner          # service health
   journalctl -u gitlab-runner -f          # live logs
   gitlab-runner list                      # registered runners
   gitlab-runner verify                    # connectivity check
   gitlab-runner unregister --name $RUNNER_NAME   # remove
──────────────────────────────────────────────────────────────────
EOF
