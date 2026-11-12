#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$source = [IO.Directory]::GetParent($PSScriptRoot).FullName
$destination = Join-Path $source 'MonitoringSIP'
$archive = Join-Path $PSScriptRoot 'MonitoringSIP_1.3.2_offline_windows_x64_fb3f7d2.zip'
$expectedHash = 'E31C36D82497153E96AFB0D7308184E56549D63179DF48F18BEC2002557ACFC9'

function Test-OfflineKit([string]$Path) {
    foreach ($dir in '.', 'app', 'runtime', 'runtime\windows', 'vendor', 'vendor\flask') {
        $item = Join-Path $Path $dir
        if (-not [IO.Directory]::Exists($item) -or
            ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    }
    foreach ($file in 'PROFILE.txt', 'VERSION.txt', 'start_windows.bat', 'run.py', 'app\release_install.py',
             'app\server.py', 'runtime\windows\python.exe', 'vendor\flask\__init__.py') {
        $item = Join-Path $Path $file
        if (-not [IO.File]::Exists($item) -or
            ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    }
    $profile = [IO.File]::ReadAllText((Join-Path $Path 'PROFILE.txt')).Trim()
    $version = [IO.File]::ReadAllText((Join-Path $Path 'VERSION.txt'))
    return $profile -ceq 'public_node' -and $version.Contains(' 1.3.2 (fb3f7d2),')
}

if (Test-Path -LiteralPath $destination) {
    if (-not (Test-OfflineKit $destination)) {
        throw 'The MonitoringSIP path already exists and is incomplete or from another release. Move it aside and keep its data before retrying.'
    }
    return
}
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    throw 'The bundled Windows offline ZIP is missing. Extract the entire GitHub Code ZIP and try again.'
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stageName = '.MonitoringSIP-setup-' + [Guid]::NewGuid().ToString('N')
$stage = Join-Path $source $stageName
$stream = [IO.File]::OpenRead($archive)
try {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '') }
    finally { $sha.Dispose() }
    if ($hash -cne $expectedHash) { throw 'The bundled Windows offline ZIP did not match its expected SHA-256.' }

    Write-Output 'Preparing the offline Windows kit...'
    $stream.Position = 0
    $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $true)
    try { [IO.Compression.ZipFileExtensions]::ExtractToDirectory($zip, $stage) }
    finally { $zip.Dispose() }
    $candidate = Join-Path $stage 'MonitoringSIP'
    if (-not (Test-OfflineKit $candidate)) { throw 'The extracted Windows kit is incomplete.' }
    try {
        [IO.Directory]::Move($candidate, $destination)
    } catch {
        # Another launcher can win the rename. Reuse its complete kit.
        if (-not (Test-OfflineKit $destination)) { throw }
    }
} finally {
    $stream.Dispose()
    if (Test-Path -LiteralPath $stage -PathType Container) {
        $resolved = (Resolve-Path -LiteralPath $stage).ProviderPath
        if ([IO.Directory]::GetParent($resolved).FullName -eq $source -and
            [IO.Path]::GetFileName($resolved) -eq $stageName -and
            -not ([IO.File]::GetAttributes($resolved) -band [IO.FileAttributes]::ReparsePoint)) {
            [IO.Directory]::Delete($resolved, $true)
        }
    }
}
