#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [Parameter(Mandatory, ParameterSetName = 'Check')]
    [string]$DataDir,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'Check')]
    [string]$MasterIP,

    [Parameter(Mandatory, ParameterSetName = 'Check')]
    [switch]$Check,

    [Parameter(Mandatory, ParameterSetName = 'Refresh')]
    [switch]$Refresh,

    [Parameter(Mandatory, ParameterSetName = 'Remove')]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0
Add-Type -AssemblyName System.Numerics

$root = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Inei-PingFirewall'
$installedScript = Join-Path $root 'configure_ping_windows.ps1'
$settingsFile = Join-Path $root 'settings.json'
$pendingFile = Join-Path $root 'pending'
$systemPowerShell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$taskArguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $installedScript + '" -Refresh'
$taskName = 'Inei Ping Firewall'
$ownerMarker = 'Managed by Inei Ping Firewall'
$rulePrefix = 'Inei.PingFirewall.'
$trustedPrincipals = @('S-1-5-18', 'S-1-5-32-544') # SYSTEM and Administrators
$utf8 = [Text.UTF8Encoding]::new($false, $true)

function Confirm-LocalDirectory([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')) {
        throw 'DataDir must be an absolute path on a local fixed drive.'
    }
    $directory = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
    if ([IO.DriveInfo]::new($directory.Root.FullName).DriveType -ne [IO.DriveType]::Fixed) {
        throw 'DataDir must be on a local fixed drive.'
    }
    for ($part = $directory; $null -ne $part; $part = $part.Parent) {
        if (-not $part.Exists -or ($part.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'DataDir must exist and cannot pass through a junction or symbolic link.'
        }
    }
    $directory.FullName
}

function Read-LimitedText([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Expected a regular local JSON file.'
    }
    $share = [IO.FileShare]::Read -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($item.FullName, 'Open', 'Read', $share)
    try {
        if ($stream.Length -gt 65536) { throw 'The JSON file exceeds 64 KiB.' }
        $reader = [IO.StreamReader]::new($stream, $utf8, $false, 1024, $true)
        try { $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function ConvertTo-TrustedAddresses([object[]]$Addresses) {
    if ($Addresses.Count -gt 1024) { throw 'At most 1024 trusted addresses are supported.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($value in $Addresses) {
        $ip = $null
        if ($value -isnot [string] -or $value -cnotmatch '^[0-9a-fA-F:.]+$' -or
            -not [Net.IPAddress]::TryParse($value, [ref]$ip)) {
            throw 'A trusted address is not a literal IPv4 or IPv6 address.'
        }
        if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            if ($ip.ToString() -cne $value -or $ip.Equals([Net.IPAddress]::Any) -or
                $ip.Equals([Net.IPAddress]::Broadcast) -or $ip.GetAddressBytes()[0] -ge 224) {
                throw 'A trusted IPv4 address must be a canonical unicast literal.'
            }
        } elseif ($ip.IsIPv4MappedToIPv6 -or $ip.IsIPv6Multicast -or $ip.Equals([Net.IPAddress]::IPv6Any)) {
            throw 'A trusted IPv6 address must be an unscoped unicast literal.'
        }
        if (-not $seen.Add($ip.ToString())) { throw 'A trusted address appears more than once.' }
    }
    $seen | Sort-Object
}

function Get-TrustedAddresses([string]$Directory, [string]$Bootstrap) {
    $path = Join-Path $Directory 'ping-trust.json'
    if (-not (Test-Path -LiteralPath $path)) {
        if (-not $Bootstrap) { throw 'No ping-trust.json found. Existing rules are unchanged.' }
        ConvertTo-TrustedAddresses @($Bootstrap)
        return
    }
    $raw = Read-LimitedText $path
    # Accept only the fixed JSON object emitted by Inei, including an empty array.
    if ($raw -cnotmatch '\A\s*\{\s*"addresses"\s*:\s*\[\s*(?:"[0-9A-Fa-f:.]+"(?:\s*,\s*"[0-9A-Fa-f:.]+")*)?\s*\]\s*\}\s*\z') {
        throw 'Expected a JSON object containing only an addresses array of literal IPs.'
    }
    ConvertTo-TrustedAddresses (ConvertFrom-Json -InputObject $raw).addresses
}

function ConvertTo-IpNumber([Net.IPAddress]$Ip) {
    $number = [System.Numerics.BigInteger]::Zero
    foreach ($octet in $Ip.GetAddressBytes()) { $number = $number * 256 + $octet }
    $number
}

function ConvertFrom-IpNumber([System.Numerics.BigInteger]$Number, [int]$Size) {
    $bytes = [byte[]]::new($Size)
    for ($offset = $Size - 1; $offset -ge 0; $offset--) {
        $bytes[$offset] = [byte]($Number % 256)
        $Number = [System.Numerics.BigInteger]::Divide($Number, 256)
    }
    [Net.IPAddress]::new($bytes).ToString()
}

function Get-AddressRange($Start, $End, [int]$Size) {
    $low = ConvertFrom-IpNumber $Start $Size
    if ($Start -eq $End) { return $low }
    $high = ConvertFrom-IpNumber $End $Size
    "$low-$high"
}

function Get-Complement([string[]]$Trusted, [int]$Size) {
    if ($Trusted.Count -eq 0) { return 'Any' } # This rule is restricted to one ICMP family.
    $numbers = @($Trusted | ForEach-Object { ConvertTo-IpNumber ([Net.IPAddress]::Parse($_)) } | Sort-Object)
    $start = [System.Numerics.BigInteger]::Zero
    $last = [System.Numerics.BigInteger]::Pow(256, $Size) - 1
    foreach ($number in $numbers) {
        if ($start -lt $number) { Get-AddressRange $start ($number - 1) $Size }
        $start = $number + 1
    }
    if ($start -le $last) { Get-AddressRange $start $last $Size }
}

function Get-RulePlan([string[]]$Addresses) {
    foreach ($family in 4, 6) {
        $size = 4
        $type = '8'
        if ($family -eq 6) { $size = 16; $type = '128' }
        $allow = @($Addresses | Where-Object { $_.Contains(':') -eq ($family -eq 6) })
        $scopes = @{ Allow = $allow; Block = @(Get-Complement $allow $size) }
        foreach ($action in 'Block', 'Allow') {
            $scope = $scopes[$action]
            # Bounded lists also keep large IPv6 policies within manageable rule sizes.
            for ($start = 0; $start -lt $scope.Count; $start += 128) {
                $part = [int]($start / 128)
                $end = [Math]::Min($start + 127, $scope.Count - 1)
                [pscustomobject]@{
                    Name = "$($rulePrefix)IPv$family.$action.$part"
                    Action = $action
                    Protocol = "ICMPv$family"
                    IcmpType = $type
                    RemoteAddress = @($scope[$start..$end])
                    Enabled = 'True'
                }
            }
        }
    }
}

function Write-AtomicBytes([string]$Path, [byte[]]$Bytes) {
    $temp = Join-Path $root ([Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        [IO.File]::WriteAllBytes($temp, $Bytes)
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { [IO.File]::Delete($temp) }
}

function Confirm-ProtectedDirectory {
    Confirm-LocalDirectory $root | Out-Null
    $security = Get-Acl -LiteralPath $root
    if (-not $security.AreAccessRulesProtected -or
        $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trustedPrincipals) {
        throw 'The Inei ProgramData directory has an unexpected owner or inherited access.'
    }
    foreach ($ace in $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin $trustedPrincipals) {
            throw 'The Inei ProgramData directory permits unexpected access.'
        }
    }
}

function New-ProtectedDirectory {
    if (-not [IO.Directory]::Exists($root)) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        foreach ($sid in $trustedPrincipals) {
            $ace = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
                'ContainerInherit, ObjectInherit', 'None', 'Allow')
            $security.AddAccessRule($ace)
        }
        [IO.Directory]::CreateDirectory($root, $security) | Out-Null
    }
    Confirm-ProtectedDirectory
}

function Get-OwnedRules {
    foreach ($rule in (Get-NetFirewallRule -PolicyStore PersistentStore |
                       Where-Object Name -like "$rulePrefix*")) {
        if ($rule.Description -cne $ownerMarker -or
            $rule.Name -cnotmatch '^Inei\.PingFirewall\.IPv[46]\.(Allow\.\d+|Block\.\d+(\.Stage\.[a-f0-9]{32})?)$') {
            throw "Firewall rule name collision: $($rule.Name)"
        }
        $port = $rule | Get-NetFirewallPortFilter
        $address = $rule | Get-NetFirewallAddressFilter
        [pscustomobject]@{
            Name = $rule.Name
            Action = [string]$rule.Action
            Protocol = [string]$port.Protocol
            IcmpType = @($port.IcmpType)
            RemoteAddress = @($address.RemoteAddress)
            Enabled = [string]$rule.Enabled
        }
    }
}

function Set-OwnedRule($Rule, [bool]$Exists) {
    $params = @{
        Name = $Rule.Name
        PolicyStore = 'PersistentStore'
        Direction = 'Inbound'
        Action = $Rule.Action
        Protocol = $Rule.Protocol
        IcmpType = $Rule.IcmpType
        RemoteAddress = $Rule.RemoteAddress
        Enabled = $Rule.Enabled
        Profile = 'Any'
    }
    if ($Exists) { Set-NetFirewallRule @params | Out-Null }
    else { New-NetFirewallRule @params -DisplayName $Rule.Name -Description $ownerMarker | Out-Null }
}

function Set-OwnedRules([object[]]$Plan, [object[]]$Existing) {
    $known = @{}
    foreach ($rule in $Existing) { $known[$rule.Name] = $rule }

    # Rule chunks can move addresses between rules. Keep both complete deny
    # scopes in force until the replacement chunks have all been written.
    $stage = [Guid]::NewGuid().ToString('N')
    foreach ($rule in $Plan | Where-Object { $_.Action -eq 'Block' -and $_.Name -notlike '*.Stage.*' }) {
        $guard = $rule.PSObject.Copy()
        $guard.Name = $rule.Name + '.Stage.' + $stage
        Set-OwnedRule $guard $false
        $known[$guard.Name] = $guard
    }
    $keep = @{}
    foreach ($action in 'Block', 'Allow') {
        foreach ($rule in $Plan | Where-Object Action -eq $action) {
            $keep[$rule.Name] = $true
            Set-OwnedRule $rule $known.ContainsKey($rule.Name)
        }
    }
    foreach ($action in 'Allow', 'Block') {
        foreach ($rule in $known.Values | Where-Object Action -eq $action) {
            if (-not $keep.ContainsKey($rule.Name)) {
                Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name
            }
        }
    }
}

function Get-OwnedTask {
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        $actions = @($task.Actions)
        if ($task.Description -cne $ownerMarker -or $actions.Count -ne 1 -or
            $actions[0].Execute -ine $systemPowerShell -or $actions[0].Arguments -cne $taskArguments) {
            throw "Scheduled task name collision: $taskName"
        }
    }
    $task
}

function Register-RefreshTask {
    $action = New-ScheduledTaskAction -Execute $systemPowerShell -WorkingDirectory $root -Argument $taskArguments
    $trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Description $ownerMarker `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
}

if ($Check) {
    $directory = Confirm-LocalDirectory $DataDir
    $addresses = @(Get-TrustedAddresses $directory $MasterIP)
    [pscustomobject]@{ Addresses = $addresses; Rules = @(Get-RulePlan $addresses) } | ConvertTo-Json -Depth 5
    return
}

if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run the installer with Windows PowerShell (powershell.exe).' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$administrator = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $identity.IsSystem -and -not $administrator.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run the installer from an elevated Windows PowerShell.'
}

if ($Refresh -or $Remove) {
    if (-not [IO.Directory]::Exists($root)) { return }
    Confirm-ProtectedDirectory
} else {
    $directory = Confirm-LocalDirectory $DataDir
    if ([IO.Directory]::Exists($root)) { Confirm-ProtectedDirectory }
    else {
        Get-TrustedAddresses $directory $MasterIP | Out-Null
        New-ProtectedDirectory
    }
}

# The task and an interactive installer cannot change the policy concurrently.
$lock = [IO.File]::Open((Join-Path $root 'lock'), 'OpenOrCreate', 'Write', 'None')
try {
    if ($Remove) {
        $task = Get-OwnedTask
        $rules = @(Get-OwnedRules)
        try {
            Set-OwnedRules @() $rules
            if ($task) { Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false }
        } catch {
            try { Set-OwnedRules $rules @(Get-OwnedRules) }
            catch { Write-Warning "Could not restore previous Inei firewall rules: $_" }
            throw
        }
        [IO.File]::Delete($settingsFile)
        [IO.File]::Delete($pendingFile)
        [IO.File]::Delete($installedScript)
        return
    }

    $priorState = $null
    if ([IO.File]::Exists($settingsFile)) { $priorState = Read-LimitedText $settingsFile | ConvertFrom-Json }
    if ([IO.File]::Exists($pendingFile)) {
        # settings.json is atomically published after the canonical rules. It
        # therefore identifies the last complete policy after an interruption.
        $stablePlan = @()
        if ($priorState) { $stablePlan = @(Get-RulePlan @($priorState.addresses)) }
        Set-OwnedRules $stablePlan @(Get-OwnedRules)
        [IO.File]::Delete($pendingFile)
    }
    if ($Refresh) {
        if (-not $priorState) { throw 'The Inei ping firewall is not configured.' }
        $directory = Confirm-LocalDirectory $priorState.data_dir
    }
    $addresses = @(Get-TrustedAddresses $directory $MasterIP)
    $changed = -not $priorState -or ($addresses -join ',') -cne (@($priorState.addresses) -join ',')
    if ($Refresh -and -not $changed) { return }

    $task = Get-OwnedTask
    $priorRules = @()
    $rulesTouched = $false
    $scriptTouched = $false
    $settingsTouched = $false
    $priorScript = $null
    if (-not $Refresh -and [IO.File]::Exists($installedScript)) {
        $priorScript = [IO.File]::ReadAllBytes($installedScript)
    }
    try {
        if ($changed) {
            if ((Get-Service -Name MpsSvc).Status -ne 'Running') {
                throw 'Windows Firewall service is not running.'
            }
            foreach ($profile in (Get-NetFirewallProfile -PolicyStore ActiveStore)) {
                if ([string]$profile.Enabled -eq 'False') {
                    throw "Windows Firewall is disabled for profile $($profile.Name)."
                }
                if ([string]$profile.AllowLocalFirewallRules -eq 'False') {
                    throw "Firewall profile $($profile.Name) requires centrally managed rules."
                }
                if ([string]$profile.AllowInboundRules -eq 'False' -and $addresses.Count) {
                    throw "Firewall profile $($profile.Name) ignores inbound allow rules."
                }
            }
            $priorRules = @(Get-OwnedRules)
            $plan = @(Get-RulePlan $addresses)
            Write-AtomicBytes $pendingFile ([byte[]]@())
            $rulesTouched = $true
            Set-OwnedRules $plan $priorRules
            $effective = @(Get-NetFirewallRule -PolicyStore ActiveStore |
                           Where-Object Description -ceq $ownerMarker | Select-Object -ExpandProperty Name)
            foreach ($rule in $plan) {
                if ($rule.Name -cnotin $effective) { throw "Rule is missing from the effective firewall policy: $($rule.Name)" }
            }
        }
        if (-not $Refresh) {
            Write-AtomicBytes $installedScript ([IO.File]::ReadAllBytes($PSCommandPath))
            $scriptTouched = $true
        }
        $newState = @{ data_dir = $directory; addresses = $addresses } | ConvertTo-Json -Compress
        Write-AtomicBytes $settingsFile ($utf8.GetBytes($newState))
        $settingsTouched = $true
        if (-not $Refresh -and -not $task) { Register-RefreshTask }
        if ($rulesTouched) { [IO.File]::Delete($pendingFile) }
    } catch {
        $restored = $true
        if ($rulesTouched) {
            try { Set-OwnedRules $priorRules @(Get-OwnedRules) }
            catch {
                $restored = $false
                Write-Warning "Could not restore previous Inei firewall rules: $_"
            }
        }
        if ($settingsTouched) {
            if ($priorState) {
                Write-AtomicBytes $settingsFile ($utf8.GetBytes(($priorState | ConvertTo-Json -Compress)))
            } else { [IO.File]::Delete($settingsFile) }
        }
        if ($scriptTouched) {
            if ($null -ne $priorScript) { Write-AtomicBytes $installedScript $priorScript }
            else { [IO.File]::Delete($installedScript) }
        }
        if ($rulesTouched -and $restored) { [IO.File]::Delete($pendingFile) }
        throw
    }
    Write-Output "Inei ping firewall active. Trusted addresses: $($addresses.Count)."
} finally { $lock.Dispose() }
