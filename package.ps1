param(
  [string]$OutputPath = (Join-Path $PSScriptRoot "komari-otp-login-1.0.0.zip")
)

# Explicit relative entries so the ZIP always uses forward slashes
# (Compress-Archive writes backslashes on Windows, which fails
# the plugin-market unsafe-path validation).
$entries = @(
  "komari-plugin.json",
  "script.js",
  "README.md",
  "assets/key-round.svg",
  "assets/otp-login.css",
  "assets/otp-login.js"
)

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue

$stream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create)
try {
  $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($entry in $entries) {
      $source = Join-Path $PSScriptRoot ($entry -replace '/', '\')
      if (-not (Test-Path -LiteralPath $source)) {
        throw "Missing file: $entry"
      }
      $dest = $zip.CreateEntry($entry, [System.IO.Compression.CompressionLevel]::Optimal)
      $destStream = $dest.Open()
      try {
        $bytes = [System.IO.File]::ReadAllBytes($source)
        $destStream.Write($bytes, 0, $bytes.Length)
      }
      finally {
        $destStream.Dispose()
      }
    }
  }
  finally {
    $zip.Dispose()
  }
}
finally {
  $stream.Dispose()
}

Write-Output $OutputPath
