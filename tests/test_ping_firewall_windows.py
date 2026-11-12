import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


POWERSHELL = shutil.which("powershell.exe") if sys.platform == "win32" else None
pytestmark = pytest.mark.skipif(not POWERSHELL, reason="Windows PowerShell 5.1 is required")
SCRIPT = Path(__file__).resolve().parents[1] / "offline" / "configure_ping_windows.ps1"


def check(directory, *args):
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(SCRIPT), "-Check", "-DataDir", str(directory), *args],
        capture_output=True, text=True, timeout=20,
    )


def plan(directory, addresses):
    (directory / "ping-trust.json").write_text(json.dumps({"addresses": addresses}), encoding="utf-8")
    result = check(directory)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def address_range(value):
    low, separator, high = value.partition("-")
    return int(ipaddress.ip_address(low)), int(ipaddress.ip_address(high if separator else low))


def test_windows_allow_and_block_partition_both_address_families(tmp_path):
    addresses = ["10.0.0.10", "10.0.0.11", "192.168.4.200", "fd12::1", "fd12::9"]
    rules = plan(tmp_path, addresses)["Rules"]
    for version, width, echo_type in [(4, 32, "8"), (6, 128, "128")]:
        matching = [rule for rule in rules if rule["Protocol"] == f"ICMPv{version}"]
        assert {rule["IcmpType"] for rule in matching} == {echo_type}
        intervals = sorted(
            (*address_range(scope), rule["Action"])
            for rule in matching
            for scope in rule["RemoteAddress"]
        )
        expected_allow = sorted(
            int(ipaddress.ip_address(value)) for value in addresses if ipaddress.ip_address(value).version == version
        )
        assert [first for first, last, action in intervals if action == "Allow" and first == last] == expected_allow
        assert intervals[0][0] == 0
        assert intervals[-1][1] == 2**width - 1
        assert all(left[1] + 1 == right[0] for left, right in zip(intervals, intervals[1:]))


def test_windows_bootstrap_is_explicit_and_empty_policy_denies_echo(tmp_path):
    assert check(tmp_path).returncode != 0
    result = check(tmp_path, "-MasterIP", "10.0.0.7")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["Addresses"] == ["10.0.0.7"]
    result = plan(tmp_path, [])
    assert result["Addresses"] == []
    assert [(rule["Protocol"], rule["Action"], rule["RemoteAddress"]) for rule in result["Rules"]] == [
        ("ICMPv4", "Block", ["Any"]), ("ICMPv6", "Block", ["Any"]),
    ]


def test_windows_large_snapshot_uses_bounded_rule_scopes(tmp_path):
    prefix = int(ipaddress.IPv6Address("fd12::"))
    addresses = [str(ipaddress.IPv6Address(prefix + 2 * index + 1)) for index in range(1024)]
    rules = [rule for rule in plan(tmp_path, addresses)["Rules"] if rule["Protocol"] == "ICMPv6"]
    assert sum(len(rule["RemoteAddress"]) for rule in rules if rule["Action"] == "Allow") == 1024
    assert sum(len(rule["RemoteAddress"]) for rule in rules if rule["Action"] == "Block") == 1025
    assert max(len(rule["RemoteAddress"]) for rule in rules) == 128


def test_windows_multi_chunk_update_keeps_denies_during_failure_and_recovery(tmp_path):
    base = int(ipaddress.IPv4Address("10.40.2.0"))
    previous = [str(ipaddress.IPv4Address(base + 2 * offset + 1)) for offset in range(130)]
    changed = [str(ipaddress.IPv4Address(base - 1)), *previous]
    input_path = tmp_path / "plans.json"
    input_path.write_text(json.dumps({"before": plan(tmp_path, previous)["Rules"],
                                     "after": plan(tmp_path, changed)["Rules"]}), encoding="utf-8")
    harness = tmp_path / "mock_firewall.ps1"
    harness.write_text(r"""
param($Installer, $Plans)
$ErrorActionPreference = 'Stop'
$ast = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$null, [ref]$null)
$functions = $ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -in @('Set-OwnedRule', 'Set-OwnedRules')
}, $true)
. ([scriptblock]::Create(($functions.Extent.Text -join [Environment]::NewLine)))

$plans = Get-Content -LiteralPath $Plans -Raw | ConvertFrom-Json
$rules = @{}
foreach ($rule in $plans.before) { $rules[$rule.Name] = $rule.PSObject.Copy() }
$history = [Collections.Generic.List[object]]::new()
$ownerMarker = 'Managed by Inei Ping Firewall'
$fail = $true

function Record-Denies {
    $history.Add(@($rules.Values | Where-Object {
        $_.Action -eq 'Block' -and $_.Protocol -eq 'ICMPv4'
    } | ForEach-Object { $_.RemoteAddress }))
}
function New-NetFirewallRule {
    param($Name, $PolicyStore, $Direction, $Action, $Protocol, $IcmpType, $RemoteAddress, $Enabled,
          $Profile, $DisplayName, $Description)
    if ($rules.ContainsKey($Name)) { throw 'Duplicate rule' }
    $rules[$Name] = [pscustomobject]@{
        Name=$Name; Action=$Action; Protocol=$Protocol; IcmpType=$IcmpType
        RemoteAddress=$RemoteAddress; Enabled=$Enabled
    }
    Record-Denies
}
function Set-NetFirewallRule {
    param($Name, $PolicyStore, $Direction, $Action, $Protocol, $IcmpType, $RemoteAddress, $Enabled, $Profile)
    if ($Name -eq 'Inei.PingFirewall.IPv4.Block.1' -and $script:fail) {
        $script:fail = $false
        throw 'Interrupted update'
    }
    $rules[$Name].RemoteAddress = $RemoteAddress
    Record-Denies
}
function Remove-NetFirewallRule {
    param($PolicyStore, $Name)
    $rules.Remove($Name)
    Record-Denies
}

Record-Denies
try { Set-OwnedRules $plans.after @($rules.Values) }
catch { if ($_ -notlike '*Interrupted update*') { throw } }
$interrupted = @($rules.Keys | Where-Object { $_ -like '*.Stage.*' })
if (-not $interrupted) { throw 'Interrupted update had no staging rules' }
Set-OwnedRules $plans.before @($rules.Values)
$recovered = @($rules.Keys | Sort-Object)
Set-OwnedRules $plans.after @($rules.Values)
[pscustomobject]@{
    history = $history
    recovered = $recovered
    applied = @($rules.Keys | Sort-Object)
} | ConvertTo-Json -Depth 7 -Compress
""", encoding="ascii")
    result = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(harness), "-Installer", str(SCRIPT), "-Plans", str(input_path)],
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    transcript = json.loads(result.stdout)
    plans = json.loads(input_path.read_text(encoding="utf-8"))
    assert transcript["recovered"] == sorted(rule["Name"] for rule in plans["before"])
    assert transcript["applied"] == sorted(rule["Name"] for rule in plans["after"])
    witness = int(ipaddress.IPv4Address("10.40.2.254"))
    assert all(
        any(low <= witness <= high for low, high in map(address_range, scopes))
        for scopes in transcript["history"]
    )


@pytest.mark.parametrize("bad_state", [
    '{"addresses":["10.0.0.0/24"]}',
    '{"addresses":["010.0.0.7"]}',
    '{"addresses":["fe80::1%4"]}',
    '{"addresses":["10.0.0.7"],"addresses":[]}',
    '{"addresses":"10.0.0.7"}',
])
def test_windows_rejects_bad_state_even_with_bootstrap(tmp_path, bad_state):
    (tmp_path / "ping-trust.json").write_text(bad_state, encoding="utf-8")
    assert check(tmp_path, "-MasterIP", "10.0.0.7").returncode != 0
