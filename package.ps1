param(
  [string]$OutputPath = (Join-Path $PSScriptRoot "komari-otp-login-0.1.0.zip")
)

$files = @(
  (Join-Path $PSScriptRoot "komari-plugin.json"),
  (Join-Path $PSScriptRoot "script.js"),
  (Join-Path $PSScriptRoot "README.md"),
  (Join-Path $PSScriptRoot "assets")
)

Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
Compress-Archive -LiteralPath $files -DestinationPath $OutputPath -CompressionLevel Optimal
Write-Output $OutputPath
