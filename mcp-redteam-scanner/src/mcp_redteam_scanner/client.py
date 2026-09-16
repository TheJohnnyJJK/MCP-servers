"""Plain HTTP client for a running /qualify-compatible service.

Framework-agnostic on purpose: this only assumes a target accepts
POST {base_url}/qualify with a LeadPayload body and returns something
QualifyResponse can validate. It doesn't know or care whether the
target is Lead Router, a hardened variant, or a third party's own
agent built to the same contract.
"""
from __future__ import annotations

import httpx

from .schema import AttackCase, QualifyResponse


class QualifyEndpointTarget:
    """POSTs an attack case's lead payload to a live /qualify endpoint."""

    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"X-API-Key": api_key} if api_key else {}
        # Well above a normal LLM call's latency - a live LLM-scored
        # request can occasionally run long, and a false timeout here
        # would misreport a slow defense as a hard error.
        self._timeout = timeout

    def send(self, case: AttackCase) -> QualifyResponse:
        response = httpx.post(
            f"{self.base_url}/qualify",
            json=case.lead.model_dump(exclude_none=True),
            headers=self._headers,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return QualifyResponse.model_validate(response.json())
