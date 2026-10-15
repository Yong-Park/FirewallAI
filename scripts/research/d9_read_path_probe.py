"""M1.2 research probe for decision D9 (firewall read path). Read-only, non-elevated.

Usage (from the repo root, as a STANDARD user):
    uv run --frozen python scripts/research/d9_read_path_probe.py --repeat 3 --out <file.json>

What it does (all read-only):
  1. Environment facts (PowerShell version, culture, elevation) - no host or user names.
  2. Which bulk/standard NetSecurity queries a standard user can run (per filter class and store).
  3. Per-rule association (pipeline) for port and address filters, with timing and per-rule errors.
  4. The COM API (HNetCfg.FwPolicy2) rule list, with timing.
  5. Rule-level comparison COM vs ActiveStore (matching, field agreement, discrepancy categories).
  6. Windows Filtering Platform filter enumeration via fwpuclnt.dll (count only).
  7. Registry stores (local and Group Policy rule keys): readability and value counts only.

Safety:
- PowerShell runs only through firewallai's audited PowerShellRunner (constant scripts, no
  ExecutionPolicy Bypass, JSON on stdin). No script modifies anything: only Get-* cmdlets, COM
  property reads, WFP enumeration, and registry KEY_READ.
- The output is SANITIZED: counts, timings, rates, and categories only. Rule names, display names,
  program paths, SIDs, addresses, and host names are never written.
"""

import argparse
import ctypes
import json
import os
import statistics
import sys
import time
import winreg
from collections import Counter
from collections.abc import Callable, Iterable
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from firewallai.collectors.windows.powershell_runner import PowerShellRunner, PowerShellScript
from firewallai.collectors.windows.privilege import is_elevated

_BIG = 64 * 1024 * 1024

# ---------------------------------------------------------------------------------------------
# Constant, read-only PowerShell bodies (research only; not registered for production use).
# Single quotes only (the runner passes the whole script as one -Command argument).
# ---------------------------------------------------------------------------------------------

ENV = PowerShellScript(
    name="research_env",
    allowed_commands=frozenset({"Get-Culture", "Get-Module", "Select-Object"}),
    body=r"""
        $m = Get-Module -ListAvailable NetSecurity | Select-Object -First 1
        [ordered]@{
            ps_version = $PSVersionTable.PSVersion.ToString()
            culture = [string](Get-Culture).Name
            netsecurity_version = [string]$m.Version
        }
""",
)

ACCESS_MATRIX = PowerShellScript(
    name="research_access_matrix",
    allowed_commands=frozenset(
        {
            "Get-NetFirewallRule",
            "Get-NetFirewallPortFilter",
            "Get-NetFirewallAddressFilter",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallServiceFilter",
            "Get-NetFirewallInterfaceTypeFilter",
            "Get-NetFirewallInterfaceFilter",
            "Get-NetFirewallSecurityFilter",
            "Get-CimInstance",
        }
    ),
    timeout_s=300,
    max_output_bytes=_BIG,
    body=r"""
        function Probe([scriptblock]$sb) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try {
                $n = @(& $sb).Count
                [ordered]@{ ok = $true; count = $n; ms = $sw.ElapsedMilliseconds }
            } catch {
                [ordered]@{
                    ok = $false
                    category = [string]$_.CategoryInfo.Category
                    error_id = [string]$_.FullyQualifiedErrorId
                    hresult = ('0x{0:X8}' -f $_.Exception.HResult)
                    ms = $sw.ElapsedMilliseconds
                }
            }
        }
        $s = @{ ErrorAction = 'Stop' }
        $ns = 'root/StandardCimv2'
        [ordered]@{
            rules_active = Probe {
                Get-NetFirewallRule -PolicyStore ActiveStore @s
            }
            rules_persistent = Probe {
                Get-NetFirewallRule -PolicyStore PersistentStore @s
            }
            rules_rsop = Probe {
                Get-NetFirewallRule -PolicyStore RSOP @s
            }
            rules_systemdefaults = Probe {
                Get-NetFirewallRule -PolicyStore SystemDefaults @s
            }
            rules_static_service = Probe {
                Get-NetFirewallRule -PolicyStore StaticServiceStore @s
            }
            rules_configurable_service = Probe {
                Get-NetFirewallRule -PolicyStore ConfigurableServiceStore @s
            }
            port_active_all = Probe {
                Get-NetFirewallPortFilter -PolicyStore ActiveStore -All @s
            }
            address_active_all = Probe {
                Get-NetFirewallAddressFilter -PolicyStore ActiveStore -All @s
            }
            application_active_all = Probe {
                Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All @s
            }
            service_active_all = Probe {
                Get-NetFirewallServiceFilter -PolicyStore ActiveStore -All @s
            }
            interfacetype_active_all = Probe {
                Get-NetFirewallInterfaceTypeFilter -PolicyStore ActiveStore -All @s
            }
            interface_active_all = Probe {
                Get-NetFirewallInterfaceFilter -PolicyStore ActiveStore -All @s
            }
            security_active_all = Probe {
                Get-NetFirewallSecurityFilter -PolicyStore ActiveStore -All @s
            }
            port_persistent_all = Probe {
                Get-NetFirewallPortFilter -PolicyStore PersistentStore -All @s
            }
            address_persistent_all = Probe {
                Get-NetFirewallAddressFilter -PolicyStore PersistentStore -All @s
            }
            port_rsop_all = Probe {
                Get-NetFirewallPortFilter -PolicyStore RSOP -All @s
            }
            port_systemdefaults_all = Probe {
                Get-NetFirewallPortFilter -PolicyStore SystemDefaults -All @s
            }
            cim_port_class_default = Probe {
                Get-CimInstance -Namespace $ns -ClassName MSFT_NetProtocolPortFilter @s
            }
            cim_address_class_default = Probe {
                Get-CimInstance -Namespace $ns -ClassName MSFT_NetAddressFilter @s
            }
            cim_app_class_default = Probe {
                Get-CimInstance -Namespace $ns -ClassName MSFT_NetApplicationFilter @s
            }
            cim_rule_class_default = Probe {
                Get-CimInstance -Namespace $ns -ClassName MSFT_NetFirewallRule @s
            }
        }
""",
)

ACTIVE_RULES = PowerShellScript(
    name="research_active_rules",
    allowed_commands=frozenset(
        {
            "Get-NetFirewallRule",
            "Get-NetFirewallApplicationFilter",
            "Get-NetFirewallServiceFilter",
            "ForEach-Object",
        }
    ),
    timeout_s=300,
    max_output_bytes=_BIG,
    body=r"""
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
        $rulesMs = $sw.ElapsedMilliseconds
        $sw.Restart()
        $apps = @(Get-NetFirewallApplicationFilter -PolicyStore ActiveStore -All -ErrorAction Stop)
        $svcs = @(Get-NetFirewallServiceFilter -PolicyStore ActiveStore -All -ErrorAction Stop)
        $filtersMs = $sw.ElapsedMilliseconds
        [ordered]@{
            rules_ms = $rulesMs
            app_service_filters_ms = $filtersMs
            rules = @(foreach ($r in $rules) {
                [ordered]@{
                    id = [string]$r.Name
                    display = [string]$r.DisplayName
                    dir = [string]$r.Direction
                    action = [string]$r.Action
                    enabled = [string]$r.Enabled
                    profile = [string]$r.Profile
                    src_type = [string]$r.PolicyStoreSourceType
                    group = [string]$r.Group
                    owner = [string]$r.Owner
                    enforcement = [string]$r.EnforcementStatus
                    status = [string]$r.PrimaryStatus
                }
            })
            apps = @(foreach ($f in $apps) {
                [ordered]@{
                    id = [string]$f.InstanceID
                    program = [string]$f.Program
                    package = [string]$f.Package
                }
            })
            svcs = @(foreach ($f in $svcs) {
                [ordered]@{ id = [string]$f.InstanceID; service = [string]$f.Service }
            })
        }
""",
)

PER_RULE = PowerShellScript(
    name="research_per_rule_association",
    allowed_commands=frozenset(
        {
            "Get-NetFirewallRule",
            "Get-NetFirewallPortFilter",
            "Get-NetFirewallAddressFilter",
            "ForEach-Object",
            "Select-Object",
        }
    ),
    timeout_s=600,
    max_output_bytes=_BIG,
    body=r"""
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $pErr = $null
        $q = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'pErr' }
        $pf = @($rules | Get-NetFirewallPortFilter @q)
        $portMs = $sw.ElapsedMilliseconds
        $sw.Restart()
        $aErr = $null
        $q = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'aErr' }
        $af = @($rules | Get-NetFirewallAddressFilter @q)
        $addrMs = $sw.ElapsedMilliseconds
        [ordered]@{
            rule_count = $rules.Count
            port_ms = $portMs
            port_errors = @($pErr).Count
            port_error_ids = @(@($pErr) |
                ForEach-Object { [string]$_.FullyQualifiedErrorId } | Select-Object -Unique)
            address_ms = $addrMs
            address_errors = @($aErr).Count
            address_error_ids = @(@($aErr) |
                ForEach-Object { [string]$_.FullyQualifiedErrorId } | Select-Object -Unique)
            port = @(foreach ($f in $pf) {
                [ordered]@{
                    id = [string]$f.InstanceID
                    protocol = [string]$f.Protocol
                    lport = @($f.LocalPort | ForEach-Object { [string]$_ })
                    rport = @($f.RemotePort | ForEach-Object { [string]$_ })
                    icmp = @($f.IcmpType | ForEach-Object { [string]$_ })
                }
            })
            addr = @(foreach ($f in $af) {
                [ordered]@{
                    id = [string]$f.InstanceID
                    laddr = @($f.LocalAddress | ForEach-Object { [string]$_ })
                    raddr = @($f.RemoteAddress | ForEach-Object { [string]$_ })
                }
            })
        }
""",
)

ASSOC_PARAM = PowerShellScript(
    name="research_association_parameter",
    allowed_commands=frozenset({"Get-NetFirewallRule", "Get-NetFirewallPortFilter"}),
    timeout_s=600,
    max_output_bytes=_BIG,
    body=r"""
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $pf = @(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rules -ErrorAction Stop)
            [ordered]@{ ok = $true; count = $pf.Count; ms = $sw.ElapsedMilliseconds }
        } catch {
            [ordered]@{
                ok = $false
                category = [string]$_.CategoryInfo.Category
                error_id = [string]$_.FullyQualifiedErrorId
                ms = $sw.ElapsedMilliseconds
            }
        }
""",
)


def _pipeline(name: str, cmdlet: str, fields: str) -> PowerShellScript:
    return PowerShellScript(
        name=name,
        allowed_commands=frozenset({"Get-NetFirewallRule", cmdlet, "ForEach-Object"}),
        timeout_s=600,
        max_output_bytes=_BIG,
        body="\n".join(
            [
                "        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop",
                ")",
                "        $sw = [Diagnostics.Stopwatch]::StartNew()",
                "        $e = $null",
                "        $q = @{ ErrorAction = 'SilentlyContinue'; ErrorVariable = 'e' }",
                f"        $f = @($rules | {cmdlet} @q)",
                "        [ordered]@{ ms = $sw.ElapsedMilliseconds; count = $f.Count;",
                "            errors = @($e).Count",
                "            items = @(foreach ($x in $f) {",
                f"                [ordered]@{{ id = [string]$x.InstanceID; {fields} }}",
                "            })",
                "        }",
            ]
        ),
    )


PORT_ONLY = _pipeline(
    "research_port_pipeline", "Get-NetFirewallPortFilter", "p = [string]$x.Protocol"
)
ADDR_ONLY = _pipeline(
    "research_address_pipeline", "Get-NetFirewallAddressFilter", "n = @($x.RemoteAddress).Count"
)
IFTYPE_ONLY = _pipeline(
    "research_interfacetype_pipeline",
    "Get-NetFirewallInterfaceTypeFilter",
    "t = [string]$x.InterfaceType",
)

COM_RULES = PowerShellScript(
    name="research_com_rules",
    allowed_commands=frozenset({"New-Object"}),  # COM object instantiation for property reads only
    timeout_s=300,
    max_output_bytes=_BIG,
    body=r"""
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        $items = @(foreach ($r in $fw.Rules) {
            [ordered]@{
                name = [string]$r.Name
                dir = [int]$r.Direction
                action = [int]$r.Action
                enabled = [bool]$r.Enabled
                profiles = [int]$r.Profiles
                protocol = [int]$r.Protocol
                lport = [string]$r.LocalPorts
                rport = [string]$r.RemotePorts
                laddr = [string]$r.LocalAddresses
                raddr = [string]$r.RemoteAddresses
                app = [string]$r.ApplicationName
                svc = [string]$r.serviceName
                group = [string]$r.Grouping
            }
        })
        [ordered]@{
            ms = $sw.ElapsedMilliseconds
            current_profile_types = [int]$fw.CurrentProfileTypes
            local_policy_modify_state = [int]$fw.LocalPolicyModifyState
            rules = $items
        }
""",
)

# ---------------------------------------------------------------------------------------------
# Normalization helpers (values are compared, never written to the evidence)
# ---------------------------------------------------------------------------------------------

_DIR = {"Inbound": 1, "Outbound": 2}
_ACTION = {"Allow": 1, "Block": 0}
_PROTO = {"tcp": "6", "udp": "17", "icmpv4": "1", "icmpv6": "58", "any": "256"}
_WELL_KNOWN_TOKENS = {
    "*",
    "localsubnet",
    "localsubnet4",
    "localsubnet6",
    "dns",
    "dhcp",
    "wins",
    "defaultgateway",
    "intranet",
    "internet",
    "playtodevice",
    "rpc",
    "rpc-epmap",
    "iphttps",
    "iphttpsin",
    "iphttpsout",
    "teredo",
    "edge",
    "ply2disc",
    "mdns",
}


def _norm_app(value: str) -> str:
    v = value.strip()
    if v.lower() in ("", "any"):
        return ""
    return os.path.normcase(os.path.expandvars(v))


def _norm_svc(value: str) -> str:
    v = value.strip().lower()
    return "" if v in ("", "any") else v


def _tokens(values: Iterable[str]) -> frozenset[str]:
    out: set[str] = set()
    for item in values:
        for part in str(item).split(","):
            p = part.strip().lower()
            if not p:
                continue
            out.add("*" if p in ("any", "*") else p)
    return frozenset(out) if out else frozenset({"*"})


def _is_keyword(token: str) -> bool:
    return token in _WELL_KNOWN_TOKENS or token.replace("-", "").isalpha()


def _shape(tokens: frozenset[str]) -> str:
    """Sanitized description of a token set: keywords verbatim, concrete values as kinds only."""
    kinds = sorted(
        {
            "any"
            if t == "*"
            else f"kw:{t}"
            if _is_keyword(t)
            else "range"
            if "-" in t
            else "explicit"
            for t in tokens
        }
    )
    return "+".join(kinds)


# ---------------------------------------------------------------------------------------------
# WFP and registry (read-only, ctypes / winreg)
# ---------------------------------------------------------------------------------------------


def probe_wfp() -> dict[str, Any]:
    """Open a WFP engine session and enumerate filters (count only). No objects are added."""
    result: dict[str, Any] = {}
    try:
        fw = ctypes.WinDLL("fwpuclnt.dll")
    except OSError as exc:
        return {"ok": False, "stage": "load", "error": type(exc).__name__}
    engine = wintypes.HANDLE()
    started = time.perf_counter()
    rc = fw.FwpmEngineOpen0(None, 10, None, None, ctypes.byref(engine))  # RPC_C_AUTHN_WINNT
    result["engine_open_rc"] = f"0x{rc & 0xFFFFFFFF:08X}"
    if rc != 0:
        result["ok"] = False
        return result
    try:
        enum = wintypes.HANDLE()
        rc = fw.FwpmFilterCreateEnumHandle0(engine, None, ctypes.byref(enum))
        result["create_enum_rc"] = f"0x{rc & 0xFFFFFFFF:08X}"
        if rc != 0:
            result["ok"] = False
            return result
        total = 0
        try:
            while True:
                entries = ctypes.c_void_p()
                returned = ctypes.c_uint32()
                rc = fw.FwpmFilterEnum0(
                    engine, enum, 1000, ctypes.byref(entries), ctypes.byref(returned)
                )
                if rc != 0:
                    result["enum_rc"] = f"0x{rc & 0xFFFFFFFF:08X}"
                    break
                total += returned.value
                if entries.value:
                    fw.FwpmFreeMemory0(ctypes.byref(entries))
                if returned.value < 1000:
                    break
        finally:
            fw.FwpmFilterDestroyEnumHandle0(engine, enum)
        result["ok"] = "enum_rc" not in result
        result["filter_count"] = total
    finally:
        fw.FwpmEngineClose0(engine)
        result["ms"] = round((time.perf_counter() - started) * 1000)
    return result


_REG_KEYS = {
    "local_rules": (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
        r"\FirewallPolicy\FirewallRules"
    ),
    "gpo_rules": r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
}


def probe_registry() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for label, path in _REG_KEYS.items():
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
                count = winreg.QueryInfoKey(key)[1]
                versions: Counter[str] = Counter()
                for i in range(count):
                    _, data, _ = winreg.EnumValue(key, i)
                    versions[str(data).split("|", 1)[0][:8]] += 1
                out[label] = {"ok": True, "value_count": count, "format_versions": dict(versions)}
        except FileNotFoundError:
            out[label] = {"ok": False, "error": "not_present"}
        except PermissionError:
            out[label] = {"ok": False, "error": "access_denied"}
    return out


# ---------------------------------------------------------------------------------------------
# Comparison (COM vs ActiveStore), sanitized
# ---------------------------------------------------------------------------------------------


def compare(
    active: dict[str, Any], per_rule: dict[str, Any], com: dict[str, Any]
) -> dict[str, Any]:
    apps = {a["id"]: a for a in active["apps"]}
    svcs = {s["id"]: s for s in active["svcs"]}
    ports = {p["id"]: p for p in per_rule["port"]}
    addrs = {a["id"]: a for a in per_rule["addr"]}

    def as_key(r: dict[str, Any]) -> tuple[Any, ...]:
        return (
            r["display"],
            _DIR.get(r["dir"]),
            _ACTION.get(r["action"]),
            r["enabled"] == "True",
            _norm_app(apps.get(r["id"], {}).get("program", "")),
            _norm_svc(svcs.get(r["id"], {}).get("service", "")),
        )

    def com_key(r: dict[str, Any]) -> tuple[Any, ...]:
        return (
            r["name"],
            r["dir"],
            r["action"],
            r["enabled"],
            _norm_app(r["app"]),
            _norm_svc(r["svc"]),
        )

    as_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for r in active["rules"]:
        as_by_key.setdefault(as_key(r), []).append(r)
    com_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for r in com["rules"]:
        com_by_key.setdefault(com_key(r), []).append(r)

    as_only: list[dict[str, Any]] = []
    com_only: list[dict[str, Any]] = []
    unique_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for key in set(as_by_key) | set(com_by_key):
        a, c = as_by_key.get(key, []), com_by_key.get(key, [])
        n = min(len(a), len(c))
        as_only.extend(a[n:])
        com_only.extend(c[n:])
        if len(a) == 1 and len(c) == 1:
            unique_pairs.append((a[0], c[0]))

    # Why do unmatched rules not match? Compare key components against COM-only rules that share
    # the same display name (sanitized: only the names of the differing key components).
    key_parts = ("display", "direction", "action", "enabled", "program", "service")
    com_only_by_name: dict[str, list[tuple[Any, ...]]] = {}
    for r in com_only:
        com_only_by_name.setdefault(r["name"], []).append(com_key(r))
    diff_parts: Counter[str] = Counter()
    no_same_name = 0
    for r in as_only:
        k = as_key(r)
        candidates = com_only_by_name.get(r["display"], [])
        if not candidates:
            no_same_name += 1
            continue
        best = min(candidates, key=lambda c: sum(a != b for a, b in zip(k, c, strict=True)))
        parts = [key_parts[i] for i, (a, b) in enumerate(zip(k, best, strict=True)) if a != b]
        diff_parts["+".join(parts) or "none"] += 1
        if parts == ["program"]:
            diff_parts[
                "program detail: AS="
                + ("empty" if not k[4] else "set")
                + " COM="
                + ("empty" if not best[4] else "set")
            ] += 1

    def full(p: dict[str, Any] | None, ad: dict[str, Any] | None) -> tuple[Any, ...]:
        if p is None or ad is None:
            return ("missing",)
        return (
            _PROTO.get(p["protocol"].lower(), p["protocol"]),
            _tokens(p["lport"]),
            _tokens(p["rport"]),
            _tokens(ad["laddr"]),
            _tokens(ad["raddr"]),
        )

    def com_full(c: dict[str, Any]) -> tuple[Any, ...]:
        return (
            str(c["protocol"]),
            _tokens([c["lport"]]),
            _tokens([c["rport"]]),
            _tokens([c["laddr"]]),
            _tokens([c["raddr"]]),
        )

    group_total = group_equal = 0
    rules_in_equal_groups = 0
    for key in set(as_by_key) & set(com_by_key):
        a, c = as_by_key[key], com_by_key[key]
        if len(a) != len(c):
            continue
        group_total += 1
        if Counter(full(ports.get(x["id"]), addrs.get(x["id"])) for x in a) == Counter(
            com_full(y) for y in c
        ):
            group_equal += 1
            rules_in_equal_groups += len(a)

    field_agree: Counter[str] = Counter()
    field_total: Counter[str] = Counter()
    mismatch_shapes: Counter[str] = Counter()
    for a, c in unique_pairs:
        p = ports.get(a["id"])
        ad = addrs.get(a["id"])
        if p is not None:
            as_proto = _PROTO.get(p["protocol"].lower(), p["protocol"])
            checks = {
                "protocol": (as_proto, str(c["protocol"])),
                "local_port": (_tokens(p["lport"]), _tokens([c["lport"]])),
                "remote_port": (_tokens(p["rport"]), _tokens([c["rport"]])),
            }
            for field, (x, y) in checks.items():
                field_total[field] += 1
                if x == y:
                    field_agree[field] += 1
                elif field != "protocol":
                    if not (isinstance(x, frozenset) and isinstance(y, frozenset)):
                        raise TypeError("token sets expected")
                    mismatch_shapes[f"{field}: AS={_shape(x)} vs COM={_shape(y)}"] += 1
                else:
                    mismatch_shapes["protocol"] += 1
        if ad is not None:
            for field, x, y in (
                ("local_address", _tokens(ad["laddr"]), _tokens([c["laddr"]])),
                ("remote_address", _tokens(ad["raddr"]), _tokens([c["raddr"]])),
            ):
                field_total[field] += 1
                if x == y:
                    field_agree[field] += 1
                else:
                    mismatch_shapes[f"{field}: AS={_shape(x)} vs COM={_shape(y)}"] += 1

    def categorize_as(r: dict[str, Any]) -> dict[str, Any]:
        app = apps.get(r["id"], {})
        return {
            "direction": r["dir"],
            "action": r["action"],
            "enabled": r["enabled"],
            "policy_store_source_type": r["src_type"],
            "enforcement_status": r["enforcement"],
            "primary_status": r["status"],
            "has_owner_sid": bool(r["owner"]),
            "has_package_sid": app.get("package", "") not in ("", "Any", "*"),
            "has_program": bool(_norm_app(app.get("program", ""))),
            "group_is_resource_string": r["group"].startswith("@"),
            "display_is_resource_string": r["display"].startswith("@"),
        }

    def categorize_com(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "direction": r["dir"],
            "action": r["action"],
            "enabled": r["enabled"],
            "has_program": bool(_norm_app(r["app"])),
            "group_is_resource_string": r["group"].startswith("@"),
            "name_is_resource_string": r["name"].startswith("@"),
        }

    rate = {
        f: round(field_agree[f] / field_total[f], 4) if field_total[f] else None
        for f in sorted(field_total)
    }
    return {
        "active_store_rule_count": len(active["rules"]),
        "com_rule_count": len(com["rules"]),
        "matched_by_key": len(active["rules"]) - len(as_only),
        "active_store_only_count": len(as_only),
        "com_only_count": len(com_only),
        "active_store_only": [categorize_as(r) for r in as_only],
        "com_only": [categorize_com(r) for r in com_only],
        "duplicate_keys_active_store": sum(1 for v in as_by_key.values() if len(v) > 1),
        "duplicate_keys_com": sum(1 for v in com_by_key.values() if len(v) > 1),
        "unique_pairs_compared": len(unique_pairs),
        "field_agreement_rate": rate,
        "field_compared_counts": dict(field_total),
        "mismatch_shapes": dict(mismatch_shapes.most_common()),
        "unmatched_key_diagnostics": {
            "active_store_only_without_same_named_com_only": no_same_name,
            "differing_key_components": dict(diff_parts.most_common()),
        },
        "key_groups_compared_as_multisets": group_total,
        "key_groups_with_identical_port_address_multisets": group_equal,
        "rules_in_identical_groups": rules_in_equal_groups,
        "active_store_policy_source_types": dict(Counter(r["src_type"] for r in active["rules"])),
        "active_store_enforcement_status": dict(Counter(r["enforcement"] for r in active["rules"])),
        "active_store_with_owner_sid": sum(1 for r in active["rules"] if r["owner"]),
        "active_store_inbound_enabled": sum(
            1 for r in active["rules"] if r["dir"] == "Inbound" and r["enabled"] == "True"
        ),
        "active_store_direction_enabled": dict(
            Counter(f"{r['dir']}/enabled={r['enabled']}" for r in active["rules"])
        ),
        "com_only_name_is_resource_string": sum(1 for r in com_only if r["name"].startswith("@")),
        "active_store_only_display_is_resource_string": sum(
            1 for r in as_only if r["display"].startswith("@")
        ),
        "active_store_with_package_sid": sum(
            1 for a in active["apps"] if a["package"] not in ("", "Any", "*")
        ),
    }


# ---------------------------------------------------------------------------------------------


def _timed(label: str, fn: Callable[[], Any], log: list[str]) -> Any:
    started = time.perf_counter()
    value = fn()
    log.append(f"{label}: {time.perf_counter() - started:.2f}s wall")
    return value


def _ms_stats(values: list[float]) -> dict[str, float]:
    return {
        "median_ms": round(statistics.median(values)),
        "min_ms": round(min(values)),
        "max_ms": round(max(values)),
        "runs": len(values),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Windows only.", file=sys.stderr)
        return 2
    if is_elevated():
        print(
            "Refusing to run elevated: this investigation is about standard users.", file=sys.stderr
        )
        return 2

    runner = PowerShellRunner()
    log: list[str] = []

    def run(script: PowerShellScript) -> Any:
        outcome = runner.run(script, source=f"research.{script.name}")
        if outcome.error is not None:
            raise RuntimeError(f"{script.name}: {outcome.error.code.value} {outcome.error.detail}")
        return outcome.data

    env = run(ENV)
    access = _timed("access matrix", lambda: run(ACCESS_MATRIX), log)

    timings: dict[str, list[float]] = {
        "active_rules_query": [],
        "app_and_service_filters_bulk": [],
        "per_rule_port_pipeline": [],
        "per_rule_address_pipeline": [],
        "com_rules_enumeration": [],
        "assoc_parameter_port": [],
        "wfp_filter_enum": [],
        "process_wall_active_rules": [],
        "process_wall_per_rule": [],
        "process_wall_com": [],
    }
    active = per_rule = com = assoc = wfp = None
    for _ in range(args.repeat):
        t0 = time.perf_counter()
        active = run(ACTIVE_RULES)
        timings["process_wall_active_rules"].append((time.perf_counter() - t0) * 1000)
        timings["active_rules_query"].append(active["rules_ms"])
        timings["app_and_service_filters_bulk"].append(active["app_service_filters_ms"])

        t0 = time.perf_counter()
        per_rule = run(PER_RULE)
        timings["process_wall_per_rule"].append((time.perf_counter() - t0) * 1000)
        timings["per_rule_port_pipeline"].append(per_rule["port_ms"])
        timings["per_rule_address_pipeline"].append(per_rule["address_ms"])

        t0 = time.perf_counter()
        com = run(COM_RULES)
        timings["process_wall_com"].append((time.perf_counter() - t0) * 1000)
        timings["com_rules_enumeration"].append(com["ms"])

        assoc = run(ASSOC_PARAM)
        timings["assoc_parameter_port"].append(assoc["ms"])

        wfp = probe_wfp()
        if "ms" in wfp:
            timings["wfp_filter_enum"].append(wfp["ms"])

    from concurrent.futures import ThreadPoolExecutor

    parallel_wall: list[float] = []
    pipeline_ms: dict[str, list[float]] = {"port": [], "address": [], "interfacetype": []}
    pipeline_errors: dict[str, int] = {}
    for _ in range(args.repeat):
        t0 = time.perf_counter()
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                "port": pool.submit(run, PORT_ONLY),
                "address": pool.submit(run, ADDR_ONLY),
                "interfacetype": pool.submit(run, IFTYPE_ONLY),
            }
            results = {k: f.result() for k, f in futures.items()}
        parallel_wall.append((time.perf_counter() - t0) * 1000)
        for k, v in results.items():
            pipeline_ms[k].append(v["ms"])
            pipeline_errors[k] = max(pipeline_errors.get(k, 0), v["errors"])
    iftypes = Counter(x["t"] for x in results["interfacetype"]["items"])
    timings["parallel_3_pipelines_wall"] = parallel_wall
    for k, v in pipeline_ms.items():
        timings[f"parallel_{k}_pipeline_in_process"] = v

    if active is None or per_rule is None or com is None:
        raise RuntimeError("no probe iterations ran")
    evidence = {
        "schema": "firewallai.research.d9/1",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "environment": {
            "test_environment": "TE-1 (see docs/planning/13-testing-strategy.md §4)",
            "windows_build": sys.getwindowsversion().build,
            "elevated": False,
            **env,
        },
        "sanitization": "Counts, timings, rates, and categories only. No names, paths, SIDs, "
        "addresses, or host identifiers.",
        "access_matrix": access,
        "per_rule_association": {
            "rule_count": per_rule["rule_count"],
            "port_filters_returned": len(per_rule["port"]),
            "port_errors": per_rule["port_errors"],
            "port_error_ids": per_rule["port_error_ids"],
            "address_filters_returned": len(per_rule["addr"]),
            "address_errors": per_rule["address_errors"],
            "address_error_ids": per_rule["address_error_ids"],
        },
        "parallel_pipelines": {
            "max_errors_per_pipeline": pipeline_errors,
            "interfacetype_counts": dict(iftypes),
            "interfacetype_filters_returned": results["interfacetype"]["count"],
        },
        "association_parameter_variant": {k: v for k, v in (assoc or {}).items() if k != "ms"},
        "com": {
            "rule_count": len(com["rules"]),
            "current_profile_types_bitmask": com["current_profile_types"],
            "local_policy_modify_state": com["local_policy_modify_state"],
        },
        "comparison_com_vs_active_store": compare(active, per_rule, com),
        "wfp": wfp,
        "registry": probe_registry(),
        "timings": {k: _ms_stats(v) for k, v in timings.items() if v},
        "wall_log": log,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote sanitized evidence to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
