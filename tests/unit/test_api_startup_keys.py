# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Configured invalid encryption keys must fail before the API starts."""

import base64

import pytest
from fastapi.testclient import TestClient
from kestrel_api import main


@pytest.mark.parametrize("setting", ["KESTREL_MASTER_KEY", "KESTREL_MASTER_KEY_PREVIOUS"])
@pytest.mark.parametrize("key", ["not-base64!", base64.b64encode(b"short").decode()])
def test_startup_rejects_invalid_configured_keys(monkeypatch, setting, key) -> None:
    monkeypatch.setenv(setting, key)
    with pytest.raises(ValueError, match=setting), TestClient(main.create_app()):
        pass


def test_uninitialized_checkout_can_start_without_a_key(monkeypatch) -> None:
    monkeypatch.delenv("KESTREL_MASTER_KEY", raising=False)
    monkeypatch.delenv("KESTREL_MASTER_KEY_PREVIOUS", raising=False)
    monkeypatch.setattr(main, "log_startup_warnings", lambda: None)
    with TestClient(main.create_app()) as client:
        assert client.get("/healthz").status_code == 200
