import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const script = `#!/bin/sh
set -e

echo ""
echo "  QuantumShield CLI Installer"
echo "  ==========================="
echo ""

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "  Detected: $OS $ARCH"
echo ""

# Check for Python 3.10+
check_python() {
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
      echo "  Found Python $PYTHON_VERSION"
      return 0
    else
      echo "  Found Python $PYTHON_VERSION (need 3.10+)"
      return 1
    fi
  else
    return 1
  fi
}

if check_python; then
  echo "  Installing QuantumShield via pip..."
  echo ""
  python3 -m pip install --user quantumshield
  echo ""
  echo "  QuantumShield installed successfully!"
  echo ""
  echo "  Get started:"
  echo "    quantumshield --help"
  echo "    quantumshield login"
  echo ""
  echo "  For real PQC crypto (ML-DSA, SLH-DSA):"
  echo "    pip install quantumshield[pqc]"
  echo ""
else
  echo "  Python 3.10+ is required but was not found."
  echo ""
  echo "  Install Python first, then run:"
  echo "    pip install quantumshield"
  echo ""
  echo "  Or install Python via your package manager:"
  case "$OS" in
    Linux*)
      echo "    sudo apt install python3 python3-pip    # Debian/Ubuntu"
      echo "    sudo dnf install python3 python3-pip    # Fedora/RHEL"
      ;;
    Darwin*)
      echo "    brew install python@3.12"
      ;;
    FreeBSD*)
      echo "    pkg install python3"
      ;;
  esac
  echo ""
  exit 1
fi
`;

  return new Response(script, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'inline; filename="install.sh"',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
