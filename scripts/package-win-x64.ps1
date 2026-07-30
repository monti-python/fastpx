param(
    [Parameter(Mandatory = $false)]
    [ValidatePattern("^[A-Za-z0-9._-]+$")]
    [string]$ArchiveName = "fastpx-win-x64"
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = Split-Path -Parent $PSScriptRoot
$Executable = Join-Path `
    $RepositoryRoot `
    "target/x86_64-pc-windows-msvc/release/fastpx.exe"
$DistDirectory = Join-Path $RepositoryRoot "dist"
$StageDirectory = Join-Path $DistDirectory $ArchiveName
$Archive = Join-Path $DistDirectory "$ArchiveName.zip"
$Checksum = Join-Path $DistDirectory "$ArchiveName.sha256"

if (-not (Test-Path $Executable -PathType Leaf)) {
    throw "Release executable not found: $Executable"
}

if (Test-Path $StageDirectory) {
    Remove-Item $StageDirectory -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $StageDirectory | Out-Null
Copy-Item $Executable $StageDirectory
Copy-Item (Join-Path $RepositoryRoot "README.md") $StageDirectory
Copy-Item (Join-Path $RepositoryRoot "LICENSE") $StageDirectory

Compress-Archive `
    -Path (Join-Path $StageDirectory "*") `
    -DestinationPath $Archive `
    -CompressionLevel Optimal `
    -Force

$Digest = (Get-FileHash $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$Digest  $ArchiveName.zip" | Set-Content `
    -Path $Checksum `
    -Encoding ascii `
    -NoNewline

Write-Host "Created $Archive"
Write-Host "Created $Checksum"
