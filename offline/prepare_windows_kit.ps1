#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

$source = [IO.Directory]::GetParent($PSScriptRoot).FullName
$destination = Join-Path $source 'MonitoringSIP'
$archive = Join-Path $PSScriptRoot 'MonitoringSIP_1.4.1_offline_windows_x64_public-node.zip'
$expectedHash = '035F7985489391A9DE1E2DBDFA325387105CF0EC3024DAC5175D1D923DEE9C4F'
$brokenPanelHash = '11018E176010E965044776568398FA6533A8BB05D975A699A6A19230B2591CC9'
$fixedPanelHash = '02EC57074631624DF3E29DE6BE5F6B9D8EBD4713DDA42B2C68AE00EE7D71A9F8'

function Test-OfflineKit([string]$Path) {
    foreach ($dir in '.', 'app', 'runtime', 'runtime\windows', 'vendor', 'vendor\flask') {
        $item = Join-Path $Path $dir
        if (-not [IO.Directory]::Exists($item) -or
            ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    }
    foreach ($file in 'PROFILE.txt', 'VERSION.txt', 'start_windows.bat', 'run.py', 'app\release_install.py',
             'app\server.py', 'app\panel.html', 'runtime\windows\python.exe', 'vendor\flask\__init__.py') {
        $item = Join-Path $Path $file
        if (-not [IO.File]::Exists($item) -or
            ([IO.File]::GetAttributes($item) -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    }
    $profile = [IO.File]::ReadAllText((Join-Path $Path 'PROFILE.txt')).Trim()
    $version = [IO.File]::ReadAllText((Join-Path $Path 'VERSION.txt'))
    return $profile -ceq 'public_node' -and $version.Contains(' 1.4.1 (public-node),')
}

function Get-Sha256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-FileSha256([string]$Path) {
    $file = [IO.File]::OpenRead($Path)
    try { return Get-Sha256 $file }
    finally { $file.Dispose() }
}

function Repair-Panel([string]$Path) {
    $panel = Join-Path $Path 'app\panel.html'
    if ((Get-FileSha256 $panel) -cne $brokenPanelHash) { return }

    $fixedPanel = Join-Path $source 'panel.html'
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($panel)) ('.panel-repair-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::Copy($fixedPanel, $temporary)
        if ((Get-FileSha256 $temporary) -cne $fixedPanelHash) {
            throw 'The corrected panel did not match its expected SHA-256. Extract the entire GitHub Code ZIP.'
        }
        if ((Get-FileSha256 $panel) -ceq $brokenPanelHash) {
            [IO.File]::Replace($temporary, $panel, [NullString]::Value)
            Write-Output 'Corrected the panel in the existing 1.4.1 kit.'
        }
    } finally {
        [IO.File]::Delete($temporary)
    }
}

if (Test-Path -LiteralPath $destination) {
    if (-not (Test-OfflineKit $destination)) {
        throw 'The MonitoringSIP path already exists and is incomplete or from another release. Move it aside and keep its data before retrying.'
    }
    Repair-Panel $destination
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
    if ((Get-Sha256 $stream) -cne $expectedHash) { throw 'The bundled Windows offline ZIP did not match its expected SHA-256.' }

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
