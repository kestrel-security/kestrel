# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Pydantic model of a connector's manifest.yaml, and the loader used by
`kestrel connector validate` and the connector registry."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator


class SetupStep(BaseModel):
    """One step in an end-to-end connector setup walkthrough.

    Surfaced in the Integrations create UI so operators can mint PATs / API
    keys / Apps without leaving the product. Keep bodies actionable and
    vendor-accurate; prefer link_url for deep links into the provider console.
    """

    title: str
    body: str
    link_url: str | None = None
    link_label: str | None = None


class AuthMethodSpec(BaseModel):
    id: str
    label: str
    secret_fields: list[str] = Field(default_factory=list)
    config_fields: list[str] = Field(default_factory=list)
    # Subset of config_fields the operator may leave blank (e.g. Slack's
    # enterprise_id, which only applies to Enterprise Grid org-level tokens).
    # Every other config field is required by the create form.
    optional_config_fields: list[str] = Field(default_factory=list)
    # Human-oriented setup guide for this auth method (optional but expected
    # for every first-party connector shipped in this repo).
    setup_overview: str | None = None
    setup_steps: list[SetupStep] = Field(default_factory=list)
    # Per-field help for config_fields + secret_fields (keys must match).
    field_help: dict[str, str] = Field(default_factory=dict)
    # Optional override / elaboration of top-level required_scopes.
    scopes_note: str | None = None

    @model_validator(mode="after")
    def _optional_fields_are_declared(self) -> AuthMethodSpec:
        undeclared = sorted(set(self.optional_config_fields) - set(self.config_fields))
        if undeclared:
            raise ValueError(f"auth method {self.id!r}: optional_config_fields {undeclared} are not listed in config_fields")
        return self

    def required_config_fields(self) -> list[str]:
        optional = set(self.optional_config_fields)
        return [field for field in self.config_fields if field not in optional]


class ObjectTypeSpec(BaseModel):
    name: str
    maps_to_entity: str
    supports_incremental: bool = False


class ConnectorManifest(BaseModel):
    name: str
    display_name: str
    version: str
    description: str
    auth_methods: list[AuthMethodSpec]
    required_scopes: list[str] = Field(default_factory=list)
    object_types: list[ObjectTypeSpec]
    rate_limit_strategy: str = "fixed_delay"
    supports_events: bool = False
    remediation_actions: list[str] = Field(default_factory=list)
    example_config: dict[str, Any] = Field(default_factory=dict)
    fixtures_path: str = "fixtures/"
    # Optional path (relative to repo or docs site) for long-form setup docs.
    setup_docs: str | None = None
    # ChangeClasses this connector guarantees in /changes when fixtures/changed
    # stages the drift. Empty → inferred from object_types maps_to_entity.
    change_classes: list[str] = Field(default_factory=list)
    # Capability keys policies may declare in REQUIRES (e.g. github:branch_protection).
    provides_capabilities: list[str] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ConnectorManifest:
        path = Path(path)
        data = yaml.safe_load(path.read_text())
        return cls.model_validate(data)

    def secret_field_names(self) -> set[str]:
        """All secret field names across every auth method -- used by
        SecretRedactor (kestrel.secrets) to scrub credentials from logs, AI
        payloads, and API responses regardless of which auth method is
        active."""
        return {field for method in self.auth_methods for field in method.secret_fields}

    def auth_method(self, method_id: str) -> AuthMethodSpec | None:
        for method in self.auth_methods:
            if method.id == method_id:
                return method
        return None
