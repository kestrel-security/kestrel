# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Dashboard routes beyond create/duplicate basics: update, set-default,
layouts, widget edit/delete, export formats, duplication of widgets, and the
email schedule CRUD.
"""

from __future__ import annotations

import json
import uuid

import pytest
from kestrel.db.models.operator import OperatorRole
from kestrel.testing import api_client

WIDGET = {
    "widget_key": "open_by_severity",
    "title": "Open findings by severity",
    "viz_type": "bar",
    "query_spec": {"entity": "finding", "group_by": ["severity"]},
}


def _board(client, name: str | None = None, **extra) -> str:
    response = client.post("/api/v1/dashboards", json={"name": name or f"Board {uuid.uuid4().hex[:8]}", **extra})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _widget(client, dashboard_id: str, **overrides) -> str:
    response = client.post(f"/api/v1/dashboards/{dashboard_id}/widgets", json={**WIDGET, **overrides})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _widgets(client, dashboard_id: str) -> list[dict]:
    return client.get(f"/api/v1/dashboards/{dashboard_id}").json()["widgets"]


# --- update / set-default -------------------------------------------------


def test_update_dashboard_changes_name_and_description(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)

    response = client.patch(f"/api/v1/dashboards/{dashboard_id}", json={"name": "  Renamed  ", "description": "New words"})

    assert response.status_code == 200
    detail = client.get(f"/api/v1/dashboards/{dashboard_id}").json()
    assert detail["name"] == "Renamed"
    assert detail["description"] == "New words"


def test_analyst_cannot_publish_a_board_to_the_org(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)
    dashboard_id = _board(client)

    response = client.patch(f"/api/v1/dashboards/{dashboard_id}", json={"visibility": "org"})

    assert response.status_code == 403


def test_another_analysts_private_board_is_invisible(db_session):
    owner = api_client(db_session, OperatorRole.ANALYST)
    other = api_client(db_session, OperatorRole.ANALYST, org=owner.kestrel_org)
    dashboard_id = _board(owner)

    assert other.get(f"/api/v1/dashboards/{dashboard_id}").status_code == 404
    assert other.patch(f"/api/v1/dashboards/{dashboard_id}", json={"name": "Mine now"}).status_code == 404


def _home(client) -> str:
    return next(d["id"] for d in client.get("/api/v1/dashboards").json()["dashboards"] if d["is_default"])


def test_an_analyst_cannot_hide_or_rename_an_org_board_they_do_not_own(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)
    shared = _board(admin, name="Shared", visibility="org")

    assert analyst.patch(f"/api/v1/dashboards/{shared}", json={"visibility": "private"}).status_code == 403
    assert analyst.patch(f"/api/v1/dashboards/{shared}", json={"name": "Mine"}).status_code == 403
    detail = admin.get(f"/api/v1/dashboards/{shared}").json()
    assert (detail["name"], detail["visibility"]) == ("Shared", "org")


def test_an_analyst_cannot_take_over_home_by_seeding_it(db_session):
    # Whoever lists dashboards first creates Home; that must not make them its owner.
    analyst = api_client(db_session, OperatorRole.ANALYST)
    admin = api_client(db_session, OperatorRole.ADMIN, org=analyst.kestrel_org)
    home = _home(analyst)

    assert analyst.patch(f"/api/v1/dashboards/{home}", json={"visibility": "private"}).status_code == 403
    assert admin.get(f"/api/v1/dashboards/{home}").json()["visibility"] == "org"


def test_an_analyst_cannot_change_widgets_on_an_org_board_they_do_not_own(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)
    home = _home(admin)
    (widget, *_rest) = _widgets(admin, home)
    base = f"/api/v1/dashboards/{home}/widgets"

    assert analyst.post(base, json=WIDGET).status_code == 403
    assert analyst.patch(f"{base}/{widget['id']}", json={"title": "Defaced"}).status_code == 403
    assert analyst.delete(f"{base}/{widget['id']}").status_code == 403
    layout = {"id": widget["id"], "layout": {"x": 0, "y": 0, "w": 1, "h": 1}}
    assert analyst.put(f"/api/v1/dashboards/{home}/layout", json={"layouts": [layout]}).status_code == 403
    after = {w["id"]: w for w in _widgets(admin, home)}
    assert after[widget["id"]]["title"] == widget["title"]
    assert after[widget["id"]]["layout"] == widget["layout"]
    # Admins still can.
    assert admin.patch(f"{base}/{widget['id']}", json={"title": "Renamed"}).status_code == 200


def test_an_analyst_still_edits_their_own_board(db_session):
    analyst = api_client(db_session, OperatorRole.ANALYST)
    dashboard_id = _board(analyst)
    widget_id = _widget(analyst, dashboard_id)

    assert analyst.patch(f"/api/v1/dashboards/{dashboard_id}", json={"name": "Renamed"}).status_code == 200
    assert analyst.patch(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}", json={"title": "T"}).status_code == 200
    assert analyst.delete(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}").status_code == 204


def test_set_default_moves_the_default_flag(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    first = _board(client, visibility="org")
    second = _board(client, visibility="org")

    assert client.post(f"/api/v1/dashboards/{first}/set-default").json()["is_default"] is True
    response = client.post(f"/api/v1/dashboards/{second}/set-default")

    assert response.status_code == 200
    assert response.json()["is_default"] is True
    assert client.get(f"/api/v1/dashboards/{first}").json()["is_default"] is False


def test_set_default_is_404_for_an_unknown_board(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    assert client.post(f"/api/v1/dashboards/{uuid.uuid4()}/set-default").status_code == 404


# --- duplicate ------------------------------------------------------------


def test_duplicate_copies_widgets_and_names_the_copy(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client, name="Source board")
    _widget(client, dashboard_id, title="First")
    _widget(client, dashboard_id, widget_key="md", title="Notes", viz_type="markdown", query_spec={})

    response = client.post(f"/api/v1/dashboards/{dashboard_id}/duplicate")

    assert response.status_code == 200
    copy = response.json()
    assert copy["id"] != dashboard_id
    assert copy["name"] == "Source board (copy)"
    assert sorted(w["title"] for w in _widgets(client, copy["id"])) == ["First", "Notes"]


def test_duplicate_by_an_analyst_is_private(db_session):
    admin = api_client(db_session, OperatorRole.ADMIN)
    analyst = api_client(db_session, OperatorRole.ANALYST, org=admin.kestrel_org)
    dashboard_id = _board(admin, visibility="org")

    response = analyst.post(f"/api/v1/dashboards/{dashboard_id}/duplicate")

    assert response.status_code == 200
    assert response.json()["visibility"] == "private"


def test_duplicate_is_404_for_an_unknown_board(db_session):
    client = api_client(db_session, OperatorRole.ANALYST)

    assert client.post(f"/api/v1/dashboards/{uuid.uuid4()}/duplicate").status_code == 404


# --- widgets and layout ---------------------------------------------------


def test_update_widget_changes_title_and_query(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    widget_id = _widget(client, dashboard_id)

    response = client.patch(
        f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}",
        json={"title": "By status", "query_spec": {"entity": "finding", "group_by": ["status"]}},
    )

    assert response.status_code == 200
    (widget,) = _widgets(client, dashboard_id)
    assert widget["title"] == "By status"
    assert widget["query_spec"]["group_by"] == ["status"]


def test_update_widget_rejects_an_unknown_viz_type_and_missing_widget(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    widget_id = _widget(client, dashboard_id)

    bad = client.patch(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}", json={"viz_type": "hologram"})
    missing = client.patch(f"/api/v1/dashboards/{dashboard_id}/widgets/{uuid.uuid4()}", json={"title": "x"})

    assert bad.status_code == 400
    assert missing.status_code == 404


def test_delete_widget_removes_it(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    widget_id = _widget(client, dashboard_id)

    response = client.delete(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}")

    assert response.status_code == 204
    assert _widgets(client, dashboard_id) == []
    assert client.delete(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}").status_code == 404


def test_an_analyst_cannot_delete_a_widget_on_someone_elses_private_board(db_session):
    owner = api_client(db_session, OperatorRole.ANALYST)
    other = api_client(db_session, OperatorRole.ANALYST, org=owner.kestrel_org)
    dashboard_id = _board(owner)
    widget_id = _widget(owner, dashboard_id)

    response = other.delete(f"/api/v1/dashboards/{dashboard_id}/widgets/{widget_id}")

    assert response.status_code in (403, 404)
    assert [w["id"] for w in _widgets(owner, dashboard_id)] == [widget_id]


def test_add_a_preset_widget(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    presets = client.get("/api/v1/dashboards/presets").json()
    preset_id = next(iter(presets["presets"]))["id"]

    response = client.post(
        f"/api/v1/dashboards/{dashboard_id}/widgets",
        json={"preset_id": preset_id, "widget_key": "ignored", "title": "ignored", "viz_type": "bar"},
    )

    assert response.status_code == 200, response.text
    assert len(_widgets(client, dashboard_id)) == 1


def test_save_layouts_updates_positions(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    first = _widget(client, dashboard_id, title="A")
    second = _widget(client, dashboard_id, title="B")
    layout = {"x": 6, "y": 0, "w": 6, "h": 4}

    response = client.put(
        f"/api/v1/dashboards/{dashboard_id}/layout",
        json={"layouts": [{"id": first, "layout": layout, "sort_order": 1}, {"id": second, "sort_order": 0}]},
    )

    assert response.status_code == 200
    by_id = {w["id"]: w for w in response.json()["widgets"]}
    assert by_id[first]["layout"] == layout
    assert by_id[first]["sort_order"] == 1
    assert by_id[second]["sort_order"] == 0


def test_save_layouts_rejects_a_widget_from_another_board(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    other_widget = _widget(client, _board(client))

    response = client.put(
        f"/api/v1/dashboards/{dashboard_id}/layout",
        json={"layouts": [{"id": other_widget, "layout": {"x": 0, "y": 0, "w": 1, "h": 1}}]},
    )

    assert response.status_code == 400


# --- export ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fmt", "media", "suffix"),
    [
        ("json", "application/json", ".json"),
        ("csv", "text/csv", ".csv"),
        ("html", "text/html", ".html"),
        ("pdf", "application/pdf", ".pdf"),
        ("webhook", "application/json", "-webhook.json"),
    ],
)
def test_export_formats(db_session, fmt, media, suffix):
    client = api_client(db_session, OperatorRole.READ_ONLY)
    admin = api_client(db_session, OperatorRole.ADMIN, org=client.kestrel_org)
    dashboard_id = _board(admin, visibility="org")
    _widget(admin, dashboard_id)

    response = client.post(f"/api/v1/dashboards/{dashboard_id}/export", params={"format": fmt})

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith(media)
    assert response.headers["content-disposition"].endswith(f'{suffix}"')
    assert response.content
    if fmt == "json":
        assert json.loads(response.content)["dashboard"]["id"] == dashboard_id


def test_export_rejects_an_unknown_format_and_board(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)

    assert client.post(f"/api/v1/dashboards/{dashboard_id}/export", params={"format": "docx"}).status_code == 400
    assert client.post(f"/api/v1/dashboards/{uuid.uuid4()}/export", params={"format": "json"}).status_code == 404


# --- schedules ------------------------------------------------------------


def _schedule_body(client, **overrides) -> dict:
    return {
        "cron": "0 8 * * 1",
        "timezone": "Europe/London",
        "format": "html",
        "recipient_operator_ids": [str(client.kestrel_operator.id)],
        **overrides,
    }


def test_schedule_crud_round_trip(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    base = f"/api/v1/dashboards/{dashboard_id}/schedules"

    created = client.post(base, json=_schedule_body(client))
    assert created.status_code == 200, created.text
    schedule = created.json()
    assert schedule["dashboard_id"] == dashboard_id
    assert schedule["format"] == "html"
    assert schedule["enabled"] is True
    assert schedule["created_by_operator_id"] == str(client.kestrel_operator.id)

    listed = client.get(base).json()["schedules"]
    assert [s["id"] for s in listed] == [schedule["id"]]

    patched = client.patch(
        f"{base}/{schedule['id']}", json={"cron": "30 9 * * *", "enabled": False, "format": "pdf", "timezone": "UTC"}
    )
    assert patched.status_code == 200
    assert patched.json()["cron"] == "30 9 * * *"
    assert patched.json()["enabled"] is False
    assert patched.json()["format"] == "pdf"
    assert patched.json()["timezone"] == "UTC"

    assert client.delete(f"{base}/{schedule['id']}").status_code == 204
    assert client.get(base).json()["schedules"] == []
    assert client.delete(f"{base}/{schedule['id']}").status_code == 404


@pytest.mark.parametrize(
    "overrides",
    [
        {"recipient_operator_ids": []},
        {"timezone": "Not/AZone"},
        {"cron": "every tuesday"},
        {"format": "docx"},
        {"recipient_operator_ids": [str(uuid.uuid4())]},
    ],
    ids=["no-recipients", "bad-timezone", "bad-cron", "bad-format", "foreign-recipient"],
)
def test_create_schedule_rejects_invalid_input(db_session, overrides):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)

    response = client.post(f"/api/v1/dashboards/{dashboard_id}/schedules", json=_schedule_body(client, **overrides))

    assert response.status_code == 400


def test_create_schedule_rejects_an_operator_from_another_org(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    outsider = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)

    response = client.post(
        f"/api/v1/dashboards/{dashboard_id}/schedules",
        json=_schedule_body(client, recipient_operator_ids=[str(outsider.kestrel_operator.id)]),
    )

    assert response.status_code == 400


def test_schedule_on_an_unknown_board_is_404(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)

    response = client.post(f"/api/v1/dashboards/{uuid.uuid4()}/schedules", json=_schedule_body(client))

    assert response.status_code == 404


def test_update_schedule_validates_recipients(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    base = f"/api/v1/dashboards/{dashboard_id}/schedules"
    schedule_id = client.post(base, json=_schedule_body(client)).json()["id"]
    teammate = api_client(db_session, OperatorRole.READ_ONLY, org=client.kestrel_org)

    empty = client.patch(f"{base}/{schedule_id}", json={"recipient_operator_ids": []})
    foreign = client.patch(f"{base}/{schedule_id}", json={"recipient_operator_ids": [str(uuid.uuid4())]})
    ok = client.patch(f"{base}/{schedule_id}", json={"recipient_operator_ids": [str(teammate.kestrel_operator.id)]})

    assert empty.status_code == 400
    assert foreign.status_code == 400
    assert ok.status_code == 200
    assert ok.json()["recipient_operator_ids"] == [str(teammate.kestrel_operator.id)]


def test_update_unknown_schedule_is_404(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)

    response = client.patch(f"/api/v1/dashboards/{dashboard_id}/schedules/{uuid.uuid4()}", json={"enabled": False})

    assert response.status_code == 404


def test_update_schedule_with_an_unknown_timezone_is_400(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    base = f"/api/v1/dashboards/{dashboard_id}/schedules"
    schedule_id = client.post(base, json=_schedule_body(client)).json()["id"]

    response = client.patch(f"{base}/{schedule_id}", json={"timezone": "Not/AZone"})

    assert response.status_code == 400


def test_schedules_require_admin(db_session):
    analyst = api_client(db_session, OperatorRole.ANALYST)
    dashboard_id = _board(analyst)

    assert analyst.get(f"/api/v1/dashboards/{dashboard_id}/schedules").status_code == 403
    response = analyst.post(f"/api/v1/dashboards/{dashboard_id}/schedules", json=_schedule_body(analyst))
    assert response.status_code == 403


def test_a_schedule_is_only_reachable_through_its_own_dashboard(db_session):
    client = api_client(db_session, OperatorRole.ADMIN)
    dashboard_id = _board(client)
    other_dashboard_id = _board(client)
    schedule_id = client.post(f"/api/v1/dashboards/{dashboard_id}/schedules", json=_schedule_body(client)).json()["id"]

    wrong = f"/api/v1/dashboards/{other_dashboard_id}/schedules/{schedule_id}"
    assert client.patch(wrong, json={"enabled": False}).status_code == 404
    assert client.delete(wrong).status_code == 404
    assert client.delete(f"/api/v1/dashboards/{dashboard_id}/schedules/{schedule_id}").status_code == 204
