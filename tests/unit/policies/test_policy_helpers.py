# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""`kestrel.policies.runtime.helpers`: the shared functions every policy
sandbox gets, and the rule that unreadable data never reads as compliant.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from kestrel.policies.runtime import RestrictedPythonRuntime, worker
from kestrel.policies.runtime.helpers import (
    POLICY_HELPERS,
    POLICY_TIME,
    PolicyDataError,
    activity_status,
    application_matches,
    cluster_accounts,
    days_since,
    domain_matches,
    duration_seconds,
    email_domain,
    get_path,
    has_admin_grant,
    has_privileged_role,
    idp_account,
    in_group,
    ip_in_networks,
    is_representative,
    matches_any,
    now,
    parse_timestamp,
    pinned_now,
    trusted_last_active,
    within_last_days,
    worker_type_of,
)
from kestrel.policies.runtime.serialize import rows_to_jsonable
from kestrel.policies.testing import run_fixture_test_dict


def _ago(days: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# --- parse_timestamp --------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC), datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (datetime(2024, 1, 2, 3, 4, 5), datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (date(2024, 1, 2), datetime(2024, 1, 2, tzinfo=UTC)),
        ("2024-01-02T03:04:05Z", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02T05:04:05+02:00", datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        ("2024-01-02", datetime(2024, 1, 2, tzinfo=UTC)),
        (1704164645, datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
        (1704164645.0, datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)),
    ],
)
def test_parse_timestamp_accepts_the_shapes_rows_carry(value, expected) -> None:
    assert parse_timestamp(value) == expected


@pytest.mark.parametrize("value", [None, "", "   "])
def test_parse_timestamp_reports_missing_as_none(value) -> None:
    assert parse_timestamp(value) is None


@pytest.mark.parametrize(
    "value",
    ["not a date", "yesterday", "2024-13-45", True, float("nan"), float("inf"), 10**20, [], {}, object()],
)
def test_parse_timestamp_raises_on_malformed_input(value) -> None:
    with pytest.raises(PolicyDataError):
        parse_timestamp(value)


def test_policy_data_error_is_a_value_error() -> None:
    # Callers outside the sandbox that already handle ValueError keep working.
    assert issubclass(PolicyDataError, ValueError)


# --- days_since / within_last_days ------------------------------------------


def test_days_since_measures_elapsed_days() -> None:
    assert days_since(_ago(10)) == pytest.approx(10, abs=0.01)
    assert days_since(None) is None
    assert days_since(datetime.now(UTC) + timedelta(days=1)) < 0


def test_within_last_days_inside_and_outside_the_window() -> None:
    assert within_last_days(_ago(1), 30) is True
    assert within_last_days(_ago(29.9), 30) is True
    assert within_last_days(_ago(30.1), 30) is False
    assert within_last_days(datetime.now(UTC) + timedelta(days=1), 30) is True


def test_within_last_days_treats_missing_as_not_shown_recent() -> None:
    assert within_last_days(None, 30) is False
    assert within_last_days("", 30) is False


def test_within_last_days_raises_rather_than_guessing() -> None:
    # The copies this replaced returned True here, which read as "recent":
    # a dormant account with a garbled last-activity value looked active.
    with pytest.raises(PolicyDataError):
        within_last_days("garbled", 90)


def test_within_last_days_reads_iso_strings_the_in_process_runtime_passes_through() -> None:
    # JSON columns (setting values) reach an in-process policy as strings; the
    # subprocess runtime rehydrates them. Both must give the same answer.
    stale = _ago(200).isoformat()
    assert within_last_days(stale, 90) is False
    assert within_last_days(stale, 90) == within_last_days(datetime.fromisoformat(stale), 90)


# --- has_admin_grant / application_matches ----------------------------------


def test_has_admin_grant() -> None:
    def row(*levels):
        return {"_related": {"grants": [{"grant": {"permission_level": level}} for level in levels]}}

    assert has_admin_grant(row("read", "admin")) is True
    assert has_admin_grant(row("read", "write")) is False
    assert has_admin_grant({}) is False
    assert has_admin_grant({"_related": {"grants": None}}) is False
    assert has_admin_grant({"_related": {"grants": [{"grant": None}]}}) is False


def test_application_matches() -> None:
    crm = {"application": {"type": "harbor-crm", "name": "Sales"}}
    named = {"application": {"type": "other", "name": "Harbor Staging"}}
    other = {"application": {"type": "github", "name": "Acme"}}

    assert application_matches(crm, {"harbor-crm"}) is True
    assert application_matches(named, {"harbor-crm"}, name_contains="harbor") is True
    assert application_matches(other, {"harbor-crm"}, name_contains="harbor") is False
    assert application_matches({}, {"harbor-crm"}, name_contains="harbor") is False


# --- available in every runtime path ----------------------------------------

_HELPER_POLICY = """
POLICY_ID = "helper-probe"
SEVERITY = "low"
RESOURCE_TYPE = "identity"

def policy(resource):
    identity = resource.get("identity") or {}
    return within_last_days(identity.get("last_active_at"), 90)
"""


def _row(subject: str, last_active) -> dict:
    return {
        "_subject_id": uuid.UUID(subject),
        "_subject_type": "identity",
        "identity": {"last_active_at": last_active},
    }


_ACTIVE = "00000000-0000-0000-0000-00000000000a"
_DORMANT = "00000000-0000-0000-0000-00000000000b"
_NEVER = "00000000-0000-0000-0000-00000000000c"


def _rows() -> list[dict]:
    return [_row(_ACTIVE, _ago(5)), _row(_DORMANT, _ago(200)), _row(_NEVER, None)]


def test_every_helper_is_in_the_sandbox_namespace() -> None:
    compiled = RestrictedPythonRuntime().compile(
        'POLICY_ID = "x"\nSEVERITY = "low"\n'
        "def policy(resource):\n"
        f"    return all(callable(f) for f in [{', '.join(POLICY_HELPERS)}])\n"
    )
    assert compiled.policy_fn({}) is True


def test_helpers_work_in_the_in_process_runtime() -> None:
    runtime = RestrictedPythonRuntime()
    result = runtime.evaluate_all(runtime.compile(_HELPER_POLICY), None, uuid.uuid4(), rows=_rows())  # type: ignore[arg-type]
    assert {str(m.subject_id) for m in result.matches} == {_DORMANT, _NEVER}


def test_helpers_work_in_the_subprocess_worker() -> None:
    result = worker._run({"source_text": _HELPER_POLICY, "rows": rows_to_jsonable(_rows())})
    assert result["ok"] is True
    assert {m["subject_id"] for m in result["matches"]} == {_DORMANT, _NEVER}


def test_helpers_work_in_fixture_tests() -> None:
    fixture = {
        "rows": [
            {"_subject_id": "a", "identity": {"last_active_at": {"$days_ago": 5}}},
            {"_subject_id": "b", "identity": {"last_active_at": {"$days_ago": 200}}},
        ],
        "expected_match_subject_ids": ["b"],
    }
    assert run_fixture_test_dict(_HELPER_POLICY, fixture).passed


# --- a malformed value fails the evaluation, visibly -------------------------


def test_malformed_value_fails_the_in_process_evaluation_naming_policy_and_subject() -> None:
    runtime = RestrictedPythonRuntime()
    rows = [*_rows(), _row("00000000-0000-0000-0000-00000000000d", "garbled")]
    with pytest.raises(PolicyDataError) as excinfo:
        runtime.evaluate_all(runtime.compile(_HELPER_POLICY), None, uuid.uuid4(), rows=rows)  # type: ignore[arg-type]
    message = str(excinfo.value)
    assert "helper-probe" in message
    assert "00000000-0000-0000-0000-00000000000d" in message
    assert "garbled" in message


def test_malformed_value_fails_the_worker_evaluation_naming_the_subject() -> None:
    rows = [*_rows(), _row("00000000-0000-0000-0000-00000000000d", "garbled")]
    result = worker._run({"source_text": _HELPER_POLICY, "rows": rows_to_jsonable(rows)})
    assert result["ok"] is False
    assert "PolicyDataError" in result["error"]
    assert "00000000-0000-0000-0000-00000000000d" in result["error"]


def test_malformed_value_fails_a_fixture_test_instead_of_passing_it() -> None:
    fixture = {
        "rows": [{"_subject_id": "a", "identity": {"last_active_at": "garbled"}}],
        "expected_match_subject_ids": [],
    }
    with pytest.raises(PolicyDataError):
        run_fixture_test_dict(_HELPER_POLICY, fixture)


# --- now / pinned clock -------------------------------------------------------

_FROZEN = datetime(2026, 6, 1, 12, 0, tzinfo=UTC).timestamp()


def _policy_body(body: str) -> str:
    return _HELPER_POLICY.replace('return within_last_days(identity.get("last_active_at"), 90)', body)


def test_now_is_aware_utc_and_follows_the_pinned_clock() -> None:
    with pinned_now(_FROZEN):
        assert now() == datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
        assert days_since(datetime(2026, 5, 22, 12, 0, tzinfo=UTC)) == pytest.approx(10.0)
        assert within_last_days("2026-05-30T12:00:00Z", 2)
        assert not within_last_days("2026-05-29T11:00:00Z", 3)
    assert now().tzinfo is UTC


def test_the_sandbox_time_reads_the_pinned_clock_and_cannot_sleep() -> None:
    assert not hasattr(POLICY_TIME, "sleep")
    assert not hasattr(POLICY_TIME, "tzset")
    with pinned_now(_FROZEN):
        assert POLICY_TIME.time() == _FROZEN
        assert POLICY_TIME.time_ns() == int(_FROZEN * 1_000_000_000)
    assert POLICY_TIME.strftime("%Y", POLICY_TIME.gmtime(0)) == "1970"


def test_policies_cannot_reach_time_sleep() -> None:
    source = _policy_body("time.sleep(0)\n    return True")
    compiled = RestrictedPythonRuntime().compile(source)
    # RestrictedPython's getattr guard reads a missing attribute as None.
    with pytest.raises(TypeError, match="not callable"):
        RestrictedPythonRuntime().match_rows(compiled, _rows())


def test_match_rows_pins_one_clock_for_every_row() -> None:
    source = _policy_body("return now().year != 2001")
    compiled = RestrictedPythonRuntime().compile(source)
    frozen_2001 = datetime(2001, 1, 1, tzinfo=UTC).timestamp()
    assert RestrictedPythonRuntime().match_rows(compiled, _rows(), now=frozen_2001) == [0, 1, 2]
    assert RestrictedPythonRuntime().match_rows(compiled, _rows()) == []


def test_the_worker_honours_the_parent_clock(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import io
    import json

    source = _policy_body("return now().year != 2001")
    payload = {
        "source_text": source,
        "rows": rows_to_jsonable(_rows()),
        "mode": "match_rows",
        "now": datetime(2001, 1, 1, tzinfo=UTC).timestamp(),
    }
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    assert worker.main() == 0
    assert json.loads(capsys.readouterr().out)["matched_indices"] == [0, 1, 2]


# --- duration_seconds ---------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("P30D", 30 * 86400),
        ("PT12H", 12 * 3600),
        ("PT90M", 90 * 60),
        ("P1DT6H", 30 * 3600),
        ("P2W", 14 * 86400),
        ("PT0.5S", 0.5),
        ("pt1h", 3600),
        ("86400s", 86400),
        ("1.5s", 1.5),
    ],
)
def test_duration_seconds_reads_iso_and_protobuf(value, expected) -> None:
    assert duration_seconds(value) == pytest.approx(expected)


@pytest.mark.parametrize("value", [None, "", "  "])
def test_duration_seconds_reports_missing_as_none(value) -> None:
    assert duration_seconds(value) is None


@pytest.mark.parametrize("value", ["P1Y", "P1M", "P", "PT", "P1DT", "12", "12h", "soon", 12, 1.5, True, {}])
def test_duration_seconds_raises_on_what_it_cannot_read(value) -> None:
    with pytest.raises(PolicyDataError):
        duration_seconds(value)


# --- get_path -----------------------------------------------------------------


def test_get_path() -> None:
    row = {"identity": {"email": "a@x.com", "mfa": None, "meta": {"n": 0}}, "roles": ["x"]}
    assert get_path(row, "identity.email") == "a@x.com"
    assert get_path(row, "identity.meta.n") == 0
    assert get_path(row, "identity.mfa", "unknown") == "unknown"
    assert get_path(row, "identity.missing.deeper") is None
    assert get_path(row, "roles.0") is None
    assert get_path(None, "a") is None
    with pytest.raises(ValueError, match="non-empty dotted path"):
        get_path(row, "")


# --- email_domain / domain_matches --------------------------------------------


def test_email_domain() -> None:
    assert email_domain("Ana@EU.Acme.COM") == "eu.acme.com"
    assert email_domain("weird@local@acme.com.") == "acme.com"
    assert email_domain(None) is None
    assert email_domain(" ") is None
    for bad in ["no-at-sign", "@acme.com", "ana@", 42]:
        with pytest.raises(PolicyDataError):
            email_domain(bad)


def test_domain_matches() -> None:
    assert domain_matches("ana@eu.acme.com", ["acme.com"])
    assert domain_matches("ana@acme.com", "ACME.com")
    assert domain_matches("hooks.acme.com", [".acme.com"])
    assert not domain_matches("ana@notacme.com", ["acme.com"])
    assert not domain_matches("ana@acme.com.evil.io", ["acme.com"])
    assert not domain_matches(None, ["acme.com"])
    assert not domain_matches("ana@acme.com", [])
    with pytest.raises(PolicyDataError):
        domain_matches("ana@", ["acme.com"])


# --- ip_in_networks -----------------------------------------------------------


def test_ip_in_networks() -> None:
    assert ip_in_networks("10.1.2.3", ["10.0.0.0/8"])
    assert ip_in_networks("10.1.2.3", "10.1.2.0/24")
    assert ip_in_networks("2001:db8::1", ["192.0.2.0/24", "2001:db8::/32"])
    assert not ip_in_networks("192.168.1.1", ["10.0.0.0/8"])
    assert not ip_in_networks("10.1.2.3", ["2001:db8::/32"])
    assert not ip_in_networks(None, ["10.0.0.0/8"])
    assert ip_in_networks("10.1.2.3", ["10.1.2.3/8"])  # host bits allowed, as providers write them
    for bad_ip, nets in [("10.1.2", ["10.0.0.0/8"]), (167837955, ["10.0.0.0/8"]), ("10.1.2.3", ["10.0.0.0/33"])]:
        with pytest.raises(PolicyDataError):
            ip_in_networks(bad_ip, nets)


# --- matches_any --------------------------------------------------------------


def test_matches_any() -> None:
    assert matches_any("Prod-API", ["prod-*"])
    assert matches_any("billing-secrets", ("*-secrets", "x"))
    assert matches_any("abc", "a?c")
    assert not matches_any("staging-api", ["prod-*"])
    assert not matches_any(None, ["*"])
    with pytest.raises(PolicyDataError):
        matches_any(5, ["*"])


# --- cluster, activity, and worker-type helpers ------------------------------


def _cluster_row(**overrides) -> dict:
    base = {
        "_subject_id": "self-id",
        "identity": {"worker_type": "unknown", "last_active_at": _ago(10), "last_active_source": "login"},
        "application": {"type": "slack", "name": "Slack"},
        "roles": [],
        "groups": ["contractors-emea", "Everyone"],
        "cluster": {
            "representative_identity_id": "okta-id",
            "worker_type": "contractor",
            "accounts": [
                {"identity_id": "okta-id", "application_type": "okta", "is_disabled": True, "privileged": False},
                {"identity_id": "self-id", "application_type": "slack", "is_disabled": False, "privileged": True},
                {
                    "identity_id": "gh-id",
                    "application_type": "github",
                    "is_disabled": False,
                    "roles": ["organization_admin"],
                },
            ],
        },
    }
    base.update(overrides)
    return base


def test_trusted_last_active_rejects_profile_timestamps_and_takes_unlabeled_ones_at_face_value() -> None:
    stamp = _ago(3)
    assert trusted_last_active({"last_active_at": stamp, "last_active_source": "login"}) == stamp
    assert trusted_last_active({"last_active_at": stamp, "last_active_source": "analytics"}) == stamp
    assert trusted_last_active({"last_active_at": stamp, "last_active_source": "profile"}) is None
    assert trusted_last_active({"last_active_at": stamp}) == stamp
    assert trusted_last_active({"last_active_at": None, "last_active_source": "login"}) is None
    assert trusted_last_active(None) is None


def test_activity_status_distinguishes_never_from_unknown() -> None:
    assert activity_status({"last_active_at": _ago(3), "last_active_source": "login"}, 30) == "active"
    assert activity_status({"last_active_at": _ago(90), "last_active_source": "audit"}, 30) == "stale"
    assert activity_status({"last_active_at": None}, 30) == "never"
    assert activity_status({"last_active_at": _ago(1), "last_active_source": "profile"}, 30) == "unknown"
    assert activity_status({}, 30) == "never"
    # A whole row works too, and GitHub's audit log is only a lower bound.
    row = {"identity": {"last_active_at": None}, "application": {"type": "github"}}
    assert activity_status(row, 30) == "unknown"
    assert activity_status({"identity": {"last_active_at": _ago(3)}, "application": {"type": "github"}}, 30) == "active"
    assert activity_status({"application_type": "github", "last_active_at": None}, 30) == "unknown"
    assert activity_status({"application_type": "slack", "last_active_at": None}, 30) == "never"
    with pytest.raises(PolicyDataError):
        activity_status({"last_active_at": "yesterday"}, 30)


def test_cluster_accounts_filters_by_application_self_and_state() -> None:
    row = _cluster_row()
    assert [a["identity_id"] for a in cluster_accounts(row)] == ["okta-id", "self-id", "gh-id"]
    assert [a["identity_id"] for a in cluster_accounts(row, include_self=False)] == ["okta-id", "gh-id"]
    assert [a["identity_id"] for a in cluster_accounts(row, "github")] == ["gh-id"]
    assert [a["identity_id"] for a in cluster_accounts(row, ["okta", "github"], active_only=True)] == ["gh-id"]
    assert cluster_accounts({"identity": {}}) == []
    assert cluster_accounts({"cluster": {"accounts": None}}) == []


def test_is_representative_gates_one_finding_per_person() -> None:
    assert is_representative(_cluster_row()) is False
    assert is_representative(_cluster_row(_subject_id="okta-id")) is True
    assert is_representative({"identity": {}}) is True
    assert is_representative({"cluster": {"representative_identity_id": None}}) is True


def test_worker_type_of_prefers_the_cluster_then_the_row_then_unknown() -> None:
    assert worker_type_of(_cluster_row()) == "contractor"
    assert worker_type_of(_cluster_row(cluster={"worker_type": "unknown"}, identity={"worker_type": "guest"})) == "guest"
    assert worker_type_of({"identity": {"worker_type": None}}) == "unknown"
    assert worker_type_of({}) == "unknown"


def test_has_privileged_role_reads_the_flag_or_the_role_names() -> None:
    assert has_privileged_role({"privileged": True}) is True
    assert has_privileged_role({"privileged": False, "roles": ["organization_admin"]}) is False
    assert has_privileged_role({"roles": ["Super Administrator"]}) is True
    assert has_privileged_role({"roles": [{"name": "Org Owner"}]}) is True
    assert has_privileged_role({"roles": ["member"]}) is False
    assert has_privileged_role({}) is False


def test_in_group_matches_globs_against_group_names() -> None:
    assert in_group(_cluster_row(), "contractors-*") is True
    assert in_group(_cluster_row(), ["staff", "EVERYONE"]) is True
    assert in_group(_cluster_row(), "admins") is False
    assert in_group({"groups": None}, "*") is False


def test_idp_account_prefers_an_enabled_identity_provider_account() -> None:
    assert idp_account(_cluster_row())["identity_id"] == "okta-id"
    row = _cluster_row()
    row["cluster"]["accounts"].append(
        {"identity_id": "gws-id", "application_type": "google_workspace", "is_disabled": False}
    )
    assert idp_account(row)["identity_id"] == "gws-id"
    assert idp_account({"cluster": {"accounts": [{"application_type": "github"}]}}) is None
    assert idp_account({}) is None


def test_cluster_helpers_run_inside_the_sandbox() -> None:
    source = (
        'POLICY_ID = "cluster-helpers"\nTITLE = "t"\nSEVERITY = "low"\nRESOURCE_TYPE = "identity"\n'
        'DESCRIPTION = "d"\nREMEDIATION = "r"\n\n'
        "def policy(resource):\n"
        '    if worker_type_of(resource) != "contractor":\n'
        "        return True\n"
        "    if not cluster_accounts(resource, include_self=False):\n"
        "        return True\n"
        '    return activity_status(resource.get("identity"), 30) == "active"\n'
    )
    fixtures = {"rows": [_cluster_row(_subject_id=uuid.uuid4())], "expected_match_subject_ids": []}
    fixtures["rows"][0]["identity"]["last_active_at"] = {"$days_ago": 120}
    fixtures["expected_match_subject_ids"] = [str(fixtures["rows"][0]["_subject_id"])]
    result = run_fixture_test_dict(source, fixtures)
    assert result.passed, (result.missing, result.unexpected)
