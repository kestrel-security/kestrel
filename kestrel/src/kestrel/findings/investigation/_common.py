# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Small helpers shared by the investigation modules: operator refs and UI paths."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from kestrel.db.models.finding import FindingSubjectType
from kestrel.db.models.operator import Operator


def _operator_out(db: Session, operator_id: uuid.UUID | None) -> dict | None:
    if operator_id is None:
        return None
    operator = db.get(Operator, operator_id)
    if operator is None:
        return None
    return {"id": operator.id, "email": operator.email, "display_name": operator.display_name}


def _findings_list_path(subject_type: FindingSubjectType | str, subject_id: uuid.UUID) -> str:
    st = subject_type.value if isinstance(subject_type, FindingSubjectType) else subject_type
    return f"/findings?subject_type={st}&subject_id={subject_id}"


def _identity_explore_path(identity_id: uuid.UUID) -> str:
    return f"/explore?focus={identity_id}&focus_type=identity&direction=out"
