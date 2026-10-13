param([switch]$Live, [int]$Port = 8787)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
New-Item -ItemType Directory -Force -Path (Join-Path $projectRoot '.cache\tmp') | Out-Null
$env:TEMP = Join-Path $projectRoot '.cache\tmp'
$env:TMP = $env:TEMP
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Install the Python environment as described in README.md first.' }
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'web\dist\index.html'))) { throw 'Run npm run build inside web first.' }
if ($Live) { & $pythonPath -m controller --port $Port } else { & $pythonPath -m controller --demo --port $Port }
exit $LASTEXITCODE
