# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
import uuid

from sqlalchemy import Boolean, String
from sqlalchemy import false as sa_false
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from kestrel.db.base import Base, TimestampMixin


class Organization(Base, TimestampMixin):
    """A Kestrel deployment represents exactly one Organization (see ADR-0006:
    multi-tenancy). Kept as a first-class table from day one so multi-org
    delegation, if built, is a thin layer on the same schema later.
    """

    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String, nullable=False)
    slug: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    # When set, an operator without a second factor must enrol in TOTP right
    # after their next password sign-in (kestrel.auth.mfa).
    require_mfa: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=sa_false())
