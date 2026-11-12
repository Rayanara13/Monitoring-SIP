#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$KitZip,
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$License,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
if (-not $License) { $License = Join-Path $PSScriptRoot 'license-draft.txt' }
$KitZip = (Resolve-Path -LiteralPath $KitZip).ProviderPath
$License = (Resolve-Path -LiteralPath $License).ProviderPath
$Output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
if ([IO.Path]::GetExtension($Output) -ine '.exe') { throw 'Output must be an EXE path.' }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($KitZip)
try {
    $names = @($zip.Entries.FullName)
    if ($names -notcontains 'MonitoringSIP/runtime/windows/python.exe' -or
        $names -notcontains 'MonitoringSIP/start_windows.bat' -or
        $names -notcontains 'MonitoringSIP/VERSION.txt' -or
        $names -notcontains 'MonitoringSIP/PROFILE.txt' -or
        @($names | Where-Object { $_ -match '/runtime/(?!windows/)[^/]+/' -or
                $_ -match '(?i)(?:^|/)(?:\.env|auth\.json|victoria-role\.json|victoria_role_authority\.pem|users_data)(?:$|/)' }).Count) {
        throw 'Expected a clean public Windows x64 offline kit.'
    }
    $reader = [IO.StreamReader]::new($zip.GetEntry('MonitoringSIP/PROFILE.txt').Open())
    try { if ($reader.ReadToEnd().Trim() -cne 'public_node') { throw 'The kit must have profile public_node.' } }
    finally { $reader.Dispose() }
}
finally { $zip.Dispose() }

$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$compiler = Join-Path $framework 'csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Windows .NET Framework 4.8 x64 compiler is required.' }
$references = @('/reference:System.Windows.Forms.dll', '/reference:System.Drawing.dll', '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll', '/reference:Microsoft.CSharp.dll')
$resources = @("/resource:$KitZip,Inei.Kit.zip", "/resource:$License,Inei.License.txt")
$work = Join-Path ([IO.Path]::GetTempPath()) ('IneiSetupBuild-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null

function Write-IneiIcon([string]$Path) {
    Add-Type -AssemblyName System.Drawing
    $image = [Drawing.Bitmap]::new(32, 32)
    $canvas = [Drawing.Graphics]::FromImage($image)
    $border = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#3b82f6'), 1)
    $fill = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#101d33'))
    $crystal = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#9dc3ff'), 1.8)
    $box = [Drawing.Drawing2D.GraphicsPath]::new()
    try {
        $canvas.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $box.AddArc(1, 1, 16, 16, 180, 90)
        $box.AddArc(15, 1, 16, 16, 270, 90)
        $box.AddArc(15, 15, 16, 16, 0, 90)
        $box.AddArc(1, 15, 16, 16, 90, 90)
        $box.CloseFigure()
        $canvas.FillPath($fill, $box)
        $canvas.DrawPath($border, $box)
        $crystal.StartCap = $crystal.EndCap = [Drawing.Drawing2D.LineCap]::Round
        # Same crystal geometry as static/monitor.svg, rendered as a Win32 icon.
        foreach ($line in @(@(16,6.5,16,25.5), @(7.77,11.25,24.23,20.75), @(7.77,20.75,24.23,11.25),
            @(13.2,8.3,16,11.1), @(16,11.1,18.8,8.3), @(13.2,23.7,16,20.9), @(16,20.9,18.8,23.7),
            @(8.05,14.6,11.85,13.58), @(11.85,13.58,10.83,9.78), @(21.17,22.22,20.15,18.42), @(20.15,18.42,23.95,17.4),
            @(10.83,22.22,11.85,18.42), @(11.85,18.42,8.05,17.4), @(24.97,14.6,21.17,13.58), @(21.17,13.58,22.19,9.78))) {
            $canvas.DrawLine($crystal, [single]$line[0], [single]$line[1], [single]$line[2], [single]$line[3])
        }
        $icon = [Drawing.Icon]::FromHandle($image.GetHicon())
        $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew)
        try { $icon.Save($file) }
        finally { $file.Dispose(); $icon.Dispose() }
    }
    finally { $box.Dispose(); $crystal.Dispose(); $fill.Dispose(); $border.Dispose(); $canvas.Dispose(); $image.Dispose() }
}

try {
    $core = Join-Path $PSScriptRoot 'SetupCore.cs'
    $wizard = Join-Path $PSScriptRoot 'SetupWizard.cs'
    $integration = Join-Path $PSScriptRoot 'SetupWindows.cs'
    $stage = Join-Path $work 'IneiSetup.exe'
    $iconPath = Join-Path $work 'Inei.ico'
    Write-IneiIcon $iconPath
    $manifest = Join-Path $PSScriptRoot 'app.manifest'
    & $compiler /nologo /target:winexe /platform:x64 /optimize+ /codepage:65001 "/win32icon:$iconPath" "/win32manifest:$manifest" "/out:$stage" @references @resources $core $wizard $integration
    if ($LASTEXITCODE -ne 0) { throw 'Unable to compile Inei Setup.' }
    if ($SelfTest) {
        $test = Join-Path $work 'IneiSetupTests.exe'
        & $compiler /nologo /target:exe /platform:x64 /codepage:65001 "/out:$test" @references @resources $core $integration (Join-Path $PSScriptRoot 'SetupCoreTests.cs')
        if ($LASTEXITCODE -ne 0) { throw 'Unable to compile installer tests.' }
        & $test
        if ($LASTEXITCODE -ne 0) { throw 'Installer transaction tests failed.' }
    }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Output)) | Out-Null
    [IO.File]::Copy($stage, $Output, $true)
    [pscustomobject]@{ Path = $Output; Bytes = (Get-Item -LiteralPath $Output).Length; SHA256 = (Get-FileHash -LiteralPath $Output).Hash }
}
finally {
    $parent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ((Split-Path -Parent $work) -eq $parent -and (Split-Path -Leaf $work) -match '^IneiSetupBuild-[a-f0-9]{32}$') {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}
