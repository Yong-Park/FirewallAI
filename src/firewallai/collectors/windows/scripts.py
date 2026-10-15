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

# Rules (M1.3, ADR 0009): ONE streaming process.
#   Event 1 (stage=inventory): rule inventory + bulk-readable filters (application, service,
#     security) from ActiveStore.
#   Events 2..n (stage=detail): restricted filters (port, address, interface type, interface alias)
#     by per-rule association, in chunks of 100. Enabled inbound rules are collected first; every
#     rule is still collected. Per-rule errors are reported with category/error id.
#   Param (JSON on stdin): {"inventory_only": true} skips the detail stage.
# Detail queries run sequentially in this one process: no parallel PowerShell (M1.2 evidence).
FIREWALL_RULES = PowerShellScript(
    name="firewall_rules",
    streaming=True,
    allowed_commands=frozenset(
        {
            "Get-NetFirewallRule",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallServiceFilter",
            "Get-NetFirewallSecurityFilter",
            "Get-NetFirewallPortFilter",
            "Get-NetFirewallAddressFilter",
            "Get-NetFirewallInterfaceTypeFilter",
            "Get-NetFirewallInterfaceFilter",
            "ForEach-Object",
            "Where-Object",
            "ConvertTo-Json",
            "ConvertFrom-Json",
        }
    ),
    timeout_s=120.0,  # security-test bound; measured full scan on TE-1 was about 33 s
    max_output_bytes=16 * 1024 * 1024,  # security-test bound; measured output size in HANDOFF
    max_line_bytes=8 * 1024 * 1024,
    max_events=2_000,
    body=r"""
        $FwaiInventoryOnly = $false
        if ($FwaiParams -and $FwaiParams.inventory_only -eq $true) { $FwaiInventoryOnly = $true }
        $FwaiStop = @{ ErrorAction = 'Stop' }
        $FwaiAll = @(Get-NetFirewallRule -PolicyStore ActiveStore @FwaiStop)
        $FwaiApps = @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All @FwaiStop)
        $FwaiSvcs = @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore -All @FwaiStop)
        $FwaiSecs = @(Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -All @FwaiStop)
        FwaiEmit ([ordered]@{
            stage = 'inventory'
            rules = @(foreach ($r in $FwaiAll) {
                [ordered]@{
                    id = [string]$r.Name
                    display = [string]$r.DisplayName
                    description = [string]$r.Description
                    group = [string]$r.Group
                    direction = [string]$r.Direction
                    action = [string]$r.Action
                    enabled = [string]$r.Enabled
                    profile = [string]$r.Profile
                    source_type = [string]$r.PolicyStoreSourceType
                    enforcement = [string]$r.EnforcementStatus
                    primary_status = [string]$r.PrimaryStatus
                    edge = [string]$r.EdgeTraversalPolicy
                    has_owner = [bool]$r.Owner
                    dynamic_keywords = @(
                        $r.RemoteDynamicKeywordAddresses | ForEach-Object { [string]$_ })
                    local_only_mapping = [bool]$r.LocalOnlyMapping
                    loose_source_mapping = [bool]$r.LooseSourceMapping
                }
            })
            apps = @(foreach ($f in $FwaiApps) {
                [ordered]@{
                    id = [string]$f.InstanceID
                    program = [string]$f.Program
                    package = [string]$f.Package
                }
            })
            services = @(foreach ($f in $FwaiSvcs) {
                [ordered]@{ id = [string]$f.InstanceID; service = [string]$f.Service }
            })
            security = @(foreach ($f in $FwaiSecs) {
                [ordered]@{
                    id = [string]$f.InstanceID
                    authentication = [string]$f.Authentication
                    encryption = [string]$f.Encryption
                    override_block = [string]$f.OverrideBlockRules
                    local_user = [string]$f.LocalUser
                    remote_user = [string]$f.RemoteUser
                    remote_machine = [string]$f.RemoteMachine
                }
            })
        })
        if (-not $FwaiInventoryOnly) {
            $FwaiFirst = @($FwaiAll | Where-Object {
                ([string]$_.Direction -eq 'Inbound') -and ([string]$_.Enabled -eq 'True') })
            $FwaiRest = @($FwaiAll | Where-Object {
                -not (([string]$_.Direction -eq 'Inbound') -and ([string]$_.Enabled -eq 'True')) })
            $FwaiOrdered = @($FwaiFirst) + @($FwaiRest)
            $FwaiQuiet = @{ ErrorAction = 'SilentlyContinue' }
            $FwaiChunk = 100
            for ($i = 0; $i -lt $FwaiOrdered.Count; $i += $FwaiChunk) {
                $last = [Math]::Min($i + $FwaiChunk, $FwaiOrdered.Count) - 1
                $part = @($FwaiOrdered[$i..$last])
                $e1 = $null; $e2 = $null; $e3 = $null; $e4 = $null
                $p = @($part | Get-NetFirewallPortFilter @FwaiQuiet -ErrorVariable e1)
                $a = @($part | Get-NetFirewallAddressFilter @FwaiQuiet -ErrorVariable e2)
                $t = @($part | Get-NetFirewallInterfaceTypeFilter @FwaiQuiet -ErrorVariable e3)
                $n = @($part | Get-NetFirewallInterfaceFilter @FwaiQuiet -ErrorVariable e4)
                $pairs = @(@('port', $e1), @('address', $e2), @('iftype', $e3), @('ifalias', $e4))
                $errs = @(
                    foreach ($pair in $pairs) {
                        foreach ($x in @($pair[1])) {
                            if ($x) {
                                [ordered]@{
                                    kind = $pair[0]
                                    target = [string]$x.TargetObject.Name
                                    category = [string]$x.CategoryInfo.Category
                                    error_id = [string]$x.FullyQualifiedErrorId
                                }
                            }
                        }
                    }
                )
                FwaiEmit ([ordered]@{
                    stage = 'detail'
                    done = $last + 1
                    total = $FwaiOrdered.Count
                    ids = @($part | ForEach-Object { [string]$_.Name })
                    port = @(foreach ($x in $p) {
                        [ordered]@{
                            id = [string]$x.InstanceID
                            protocol = [string]$x.Protocol
                            local = @($x.LocalPort | ForEach-Object { [string]$_ })
                            remote = @($x.RemotePort | ForEach-Object { [string]$_ })
                            icmp = @($x.IcmpType | ForEach-Object { [string]$_ })
                            dynamic_target = [string]$x.DynamicTarget
                            dynamic_transport = [string]$x.DynamicTransport
                        }
                    })
                    address = @(foreach ($x in $a) {
                        [ordered]@{
                            id = [string]$x.InstanceID
                            local = @($x.LocalAddress | ForEach-Object { [string]$_ })
                            remote = @($x.RemoteAddress | ForEach-Object { [string]$_ })
                        }
                    })
                    iftype = @(foreach ($x in $t) {
                        [ordered]@{ id = [string]$x.InstanceID; type = [string]$x.InterfaceType }
                    })
                    ifalias = @(foreach ($x in $n) {
                        [ordered]@{
                            id = [string]$x.InstanceID
                            aliases = @($x.InterfaceAlias | ForEach-Object { [string]$_ })
                        }
                    })
                    errors = $errs
                })
            }
        }
        [ordered]@{ total = $FwaiAll.Count; inventory_only = $FwaiInventoryOnly }
""",
)

# Services per process (M1.4, human decision Q2): names of services that currently run in a
# process, used to describe service-scoped rules. Read-only CIM query against the local machine
# (no -ComputerName, no network). Only Name and ProcessId are requested.
WIN32_SERVICES = PowerShellScript(
    name="win32_services",
    allowed_commands=frozenset({"Get-CimInstance"}),
    timeout_s=15.0,
    max_output_bytes=1024 * 1024,
    body=r"""
        $FwaiProps = @('Name', 'ProcessId')
        $FwaiSvc = @(Get-CimInstance -ClassName Win32_Service -Property $FwaiProps)
        [ordered]@{
            services = @(foreach ($s in $FwaiSvc) {
                if ([long]$s.ProcessId -gt 0) {
                    [ordered]@{ name = [string]$s.Name; pid = [long]$s.ProcessId }
                }
            })
        }
""",
)

REGISTERED_SCRIPTS: tuple[PowerShellScript, ...] = (
    FIREWALL_PROFILES,
    FIREWALL_RULES,
    WIN32_SERVICES,
)
