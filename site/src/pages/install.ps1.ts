import type { APIRoute } from 'astro';

export const GET: APIRoute = () => {
  const script = `# QuantumShield CLI Installer for Windows
# Usage: irm https://quantamrkt.com/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  QuantumShield CLI Installer" -ForegroundColor Cyan
Write-Host "  ===========================" -ForegroundColor Cyan
Write-Host ""

# Check for Python
function Test-Python {
    try {
        $version = & python --version 2>&1
        if ($version -match "Python (\\d+)\\.(\\d+)") {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 10) {
                Write-Host "  Found $version" -ForegroundColor Green
                return $true
            } else {
                Write-Host "  Found $version (need 3.10+)" -ForegroundColor Yellow
                return $false
            }
        }
    } catch {
        return $false
    }
    return $false
}

if (Test-Python) {
    Write-Host "  Installing QuantumShield via pip..." -ForegroundColor White
    Write-Host ""

    & python -m pip install --user quantumshield

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "  QuantumShield installed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Get started:" -ForegroundColor White
        Write-Host "    quantumshield --help"
        Write-Host "    quantumshield login"
        Write-Host ""
        Write-Host "  For real PQC crypto (ML-DSA, SLH-DSA):" -ForegroundColor White
        Write-Host "    pip install quantumshield[pqc]"
        Write-Host ""
    } else {
        Write-Host "  Installation failed. Please try manually:" -ForegroundColor Red
        Write-Host "    pip install quantumshield"
        exit 1
    }
} else {
    Write-Host "  Python 3.10+ is required but was not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  Install Python from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  Or via winget:" -ForegroundColor Yellow
    Write-Host "    winget install Python.Python.3.12" -ForegroundColor White
    Write-Host ""
    Write-Host "  Then run:" -ForegroundColor Yellow
    Write-Host "    pip install quantumshield" -ForegroundColor White
    Write-Host ""
    exit 1
}
`;

  return new Response(script, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': 'inline; filename="install.ps1"',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
