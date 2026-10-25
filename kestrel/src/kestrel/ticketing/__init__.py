# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Outbound TicketProvider adapters."""

from kestrel.ticketing.authoring import (
    TicketAuthoringError,
    create_integration,
    decrypt_integration_token,
    get_org_integration,
    integration_out,
    rotate_token,
    update_integration,
)
from kestrel.ticketing.create import (
    MAX_TICKETS_PER_FINDING,
    TicketCreateError,
    create_ticket_for_finding,
    list_finding_tickets,
    ticket_out,
)
from kestrel.ticketing.protocol import TicketCreateRequest, TicketCreateResult, TicketProvider
from kestrel.ticketing.registry import (
    discover_ticket_providers,
    list_provider_ids,
    load_ticket_provider,
    provider_summaries,
)

__all__ = [
    "MAX_TICKETS_PER_FINDING",
    "TicketAuthoringError",
    "TicketCreateError",
    "TicketCreateRequest",
    "TicketCreateResult",
    "TicketProvider",
    "create_integration",
    "create_ticket_for_finding",
    "decrypt_integration_token",
    "discover_ticket_providers",
    "get_org_integration",
    "integration_out",
    "list_finding_tickets",
    "list_provider_ids",
    "load_ticket_provider",
    "provider_summaries",
    "rotate_token",
    "ticket_out",
    "update_integration",
]
