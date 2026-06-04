param(
    [string]$Output = "nettop-3.0.0.zip"
)

$root = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $root $Output
if (Test-Path -LiteralPath $outPath) {
    Remove-Item -LiteralPath $outPath -Force
}

$items = @(
    "nettop",
    "packaging",
    "scripts",
    "tests",
    "README.md",
    "pyproject.toml",
    "requirements.txt"
)

$paths = $items | ForEach-Object { Join-Path $root $_ }
Compress-Archive -LiteralPath $paths -DestinationPath $outPath -Force
Write-Host $outPath
