"""Registry of constant, reviewed, read-only PowerShell script bodies.

Rules (enforced by tests/security/test_powershell_scripts.py):
- Only cmdlets listed in each script's ``allowed_commands`` may appear. All of them are read-only.
- No double quotes, so the rendered script is one safe ``-Command`` argument.
- No string evaluation (``Invoke-Expression``/``iex``), no process launching, no ``Add-Type``.
- Every script body must be listed in ``REGISTERED_SCRIPTS``.
"""

from firewallai.collectors.windows.powershell_runner import PowerShellScript

# Effective (ActiveStore = local + Group Policy merged) profile settings. Enum values are cast to
# their documented integer values and mapped explicitly in Python (profile_mapping.py):
#   GpoBoolean: False=0, True=1, NotConfigured=2;  Action: NotConfigured=0, Allow=2, Block=4
# (verified read-only on the dev machine TE-1, 2026-10-14).
FIREWALL_PROFILES = PowerShellScript(
    name="firewall_profiles",
    allowed_commands=frozenset(
        {"Get-NetFirewallProfile", "ForEach-Object", "ConvertTo-Json", "ConvertFrom-Json"}
    ),
    timeout_s=30.0,
    max_output_bytes=256 * 1024,
    body=r"""
        $FwaiProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
        [ordered]@{
            profiles = @(foreach ($p in $FwaiProfiles) {
                $FwaiAliases = @($p.DisabledInterfaceAliases | ForEach-Object { [string]$_ })
                [ordered]@{
                    Name = [string]$p.Name
                    Enabled = [int]$p.Enabled
                    DefaultInboundAction = [int]$p.DefaultInboundAction
                    DefaultOutboundAction = [int]$p.DefaultOutboundAction
                    AllowInboundRules = [int]$p.AllowInboundRules
                    AllowLocalFirewallRules = [int]$p.AllowLocalFirewallRules
                    AllowLocalIPsecRules = [int]$p.AllowLocalIPsecRules
                    NotifyOnListen = [int]$p.NotifyOnListen
                    LogAllowed = [int]$p.LogAllowed
                    LogBlocked = [int]$p.LogBlocked
                    LogMaxSizeKilobytes = [long]$p.LogMaxSizeKilobytes
                    LogFileName = [string]$p.LogFileName
                    DisabledInterfaceAliases = $FwaiAliases
                }
            })
        }
""",
)

REGISTERED_SCRIPTS: tuple[PowerShellScript, ...] = (FIREWALL_PROFILES,)
