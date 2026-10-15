"""Shared progressive rule-collection driver (used by the Windows and fixture collectors).

An "event source" delivers raw events (stage=inventory, then stage=detail chunks) to a callback
and returns a ``RunOutcome`` describing how the stream ended. This driver validates, assembles,
notifies the observer, and turns every early end (cancel, timeout, failure) into explicit
NOT_COLLECTED states plus scan-level limitations. It never fills gaps with "Any".
"""

import threading
from collections.abc import Callable

from firewallai.collectors.protocols import RuleCollectionObserver, RulesResult
from firewallai.collectors.windows.powershell_runner import JsonValue, RunOutcome
from firewallai.collectors.windows.rule_mapping import RuleAssembler
from firewallai.core.results import CollectorError, CollectorErrorCode, CollectorResult
from firewallai.core.rules import (
    NotCollectedReason,
    RuleCollection,
    ScanLimitation,
    ScanLimitationCode,
)

EventSource = Callable[[Callable[[JsonValue], None], threading.Event | None, bool], RunOutcome]

BASE_LIMITATIONS: tuple[ScanLimitation, ...] = (
    ScanLimitation(
        code=ScanLimitationCode.LOCAL_POLICY_ONLY,
        detail="Local Windows Firewall policy only; external reachability is not determined.",
    ),
    ScanLimitation(
        code=ScanLimitationCode.WFP_FILTERS_NOT_OBSERVABLE,
        detail="Non-firewall WFP filters cannot be enumerated by a standard user.",
    ),
    ScanLimitation(
        code=ScanLimitationCode.SERVICE_HARDENING_NOT_EVALUATED,
        detail="Service-hardening rule stores are outside ActiveStore and not evaluated.",
    ),
    ScanLimitation(
        code=ScanLimitationCode.GROUP_POLICY_MERGE_UNVERIFIED,
        detail="Group Policy merge behavior is unverified.",
    ),
    ScanLimitation(
        code=ScanLimitationCode.ENFORCEMENT_STATUS_UNINTERPRETED,
        detail="Rule enforcement status is reported raw and not interpreted.",
    ),
)

_REASON_FOR = {
    CollectorErrorCode.CANCELLED: NotCollectedReason.CANCELLED,
}


def collect_progressively(
    source_id: str,
    event_source: EventSource,
    *,
    detail: bool,
    observer: RuleCollectionObserver | None,
    cancel: threading.Event | None,
) -> RulesResult:
    assembler = RuleAssembler(source=source_id, detail_requested=detail)

    def on_event(event: JsonValue) -> None:
        stage = event.get("stage") if isinstance(event, dict) else None
        if stage == "inventory" and not assembler.inventory_received:
            rules = assembler.ingest_inventory(event)
            if observer is not None:
                observer.inventory_ready(rules)
        elif stage == "detail" and detail:
            updated = assembler.ingest_detail(event)
            if observer is not None:
                total = int(event.get("total", 0)) if isinstance(event, dict) else 0
                observer.detail_progress(assembler.detail_done, total, updated)
        else:
            raise ValueError("unexpected stream event")

    try:
        outcome = event_source(on_event, cancel, detail)
    except ValueError as exc:  # payload/protocol violation; the child process is already killed
        outcome = RunOutcome(
            error=CollectorError(
                code=CollectorErrorCode.PARSE_ERROR, source=source_id, detail=str(exc)[:300]
            )
        )

    if not assembler.inventory_received:
        error = outcome.error or CollectorError(
            code=CollectorErrorCode.PARSE_ERROR, source=source_id, detail="no inventory received"
        )
        return CollectorResult(errors=(error,))

    limitations = list(BASE_LIMITATIONS)
    errors = list(assembler.errors)
    still_pending = assembler.pending_count()
    if outcome.error is not None:
        errors.append(outcome.error)
        reason = _REASON_FOR.get(outcome.error.code, NotCollectedReason.PHASE_FAILED)
        rules = assembler.finalize(reason)
    else:
        rules = assembler.finalize(
            NotCollectedReason.MISSING_FROM_SOURCE if detail else NotCollectedReason.NOT_REQUESTED
        )
    detail_complete = detail and outcome.error is None and still_pending == 0
    if not detail:
        limitations.append(
            ScanLimitation(
                code=ScanLimitationCode.DETAIL_NOT_COLLECTED,
                detail="Inventory-only scan: port, address, and interface filters not collected.",
            )
        )
    elif not detail_complete:
        limitations.append(
            ScanLimitation(
                code=ScanLimitationCode.DETAIL_INCOMPLETE,
                detail=f"Detail collection did not finish for {still_pending} rule(s); "
                "their filters are not collected.",
            )
        )
    if any(r.remote_dynamic_keyword_addresses for r in rules):
        limitations.append(
            ScanLimitation(
                code=ScanLimitationCode.DYNAMIC_KEYWORDS_NOT_RESOLVED,
                detail="Some rules reference dynamic keyword addresses, which are not resolved.",
            )
        )
    collection = RuleCollection(
        rules=rules,
        total_in_source=assembler.total_in_source,
        detail_requested=detail,
        detail_complete=detail_complete,
        limitations=tuple(limitations),
    )
    unique_errors = tuple(dict.fromkeys(errors))
    return CollectorResult(data=collection, errors=unique_errors, partial=bool(unique_errors))
