$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$testRoot = Join-Path $projectRoot ('.cache\tests-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff'))
if (-not [IO.Path]::GetFullPath($testRoot).StartsWith([IO.Path]::GetFullPath($projectRoot) + [IO.Path]::DirectorySeparatorChar)) { throw 'Test path must stay inside this workspace.' }
& (Join-Path $projectRoot '.venv\Scripts\python.exe') -m pytest "--basetemp=$testRoot"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Push-Location (Join-Path $projectRoot 'web')
try { npm run build; $buildResult = $LASTEXITCODE; if ($buildResult -eq 0) { npm run test:pwa; $buildResult = $LASTEXITCODE } } finally { Pop-Location }
exit $buildResult
