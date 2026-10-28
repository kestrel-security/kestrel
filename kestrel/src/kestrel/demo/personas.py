# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""One cast of characters, projected into every demo tenant.

The bundled fixtures each invented their own people, and the seams show: the
GitHub logins are scrambled against the names (``alice`` is Grace Hopper,
``carol`` is Ada Lovelace), ``frank-external`` and ``deploy-bot`` carry no email
at all, and the Microsoft 365 guest and ex-employee use *different* addresses
than the same people in Okta and Slack. Email is the only join key the identity
graph has, so those people can never collapse into one node no matter
how good the graph is.

Here the roster is the source of truth and each connector's view is derived from
it, so cross-app correlation is correct by construction rather than by careful
hand-editing of five JSON trees.

The roster is also *shaped*, not just populated: the archetypes below exist so
the shipped policy packs actually fire, and so every Explore filter, every
Findings status chip, and every change class has something real behind it.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum

# Bumping this reshuffles every generated tenant. Keep it stable so a demo
# recorded on one machine matches the one a colleague brings up.
DEFAULT_SEED = 20260828

PRIMARY_DOMAIN = "acme.example.com"
VENDOR_DOMAIN = "vendor.example.com"


class Archetype(str, Enum):
    """Why a persona exists. Each one is a demo beat somewhere in the product."""

    STAFF = "staff"
    # Admin without MFA -> the highest-severity posture finding in every pack.
    ADMIN_NO_MFA = "admin_no_mfa"
    ADMIN = "admin"
    # Active account, no login in months -> dormancy + access-review beats.
    DORMANT = "dormant"
    # Deprovisioned but still holding privilege -> the orphaned-admin beat.
    DEPROVISIONED_ADMIN = "deprovisioned_admin"
    DEPARTED = "departed"
    # Outside collaborator / guest -> external-access and sharing beats.
    EXTERNAL = "external"
    # Non-human identity -> NHI beats, and the reason `svc-` naming matters.
    SERVICE_ACCOUNT = "service_account"


@dataclass(frozen=True)
class Persona:
    """One human (or non-human) across every tenant they appear in."""

    key: str
    first_name: str
    last_name: str
    email: str
    department: str
    archetype: Archetype = Archetype.STAFF
    # Tenants this persona exists in. Not everyone is in everything -- a demo
    # where all three tenants hold identical people has no cross-app story.
    tenants: frozenset[str] = field(default_factory=lambda: frozenset({"github", "slack", "okta", "google_workspace"}))
    # Tenants that treat this person as a guest even though the company does
    # not. The two disagreeing is the whole point of
    # `cross-app-external-privileged-elsewhere`: one console sees an outsider,
    # another sees an administrator, and neither sees both.
    guest_in: frozenset[str] = field(default_factory=frozenset)

    def is_guest_in(self, tenant: str) -> bool:
        return self.is_external or tenant in self.guest_in

    @property
    def display_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    @property
    def is_external(self) -> bool:
        return self.archetype is Archetype.EXTERNAL

    @property
    def is_disabled(self) -> bool:
        return self.archetype in {Archetype.DEPROVISIONED_ADMIN, Archetype.DEPARTED}

    @property
    def is_admin(self) -> bool:
        return self.archetype in {
            Archetype.ADMIN,
            Archetype.ADMIN_NO_MFA,
            Archetype.DEPROVISIONED_ADMIN,
        }

    @property
    def has_mfa(self) -> bool:
        if self.archetype is Archetype.ADMIN_NO_MFA:
            return False
        return self.archetype not in {Archetype.SERVICE_ACCOUNT, Archetype.EXTERNAL}

    @property
    def title(self) -> str:
        if self.archetype is Archetype.SERVICE_ACCOUNT:
            return "Service account"
        if self.is_external:
            return "Contract engineer"
        return f"{self.department} engineer" if self.department != "Sales" else "Account executive"

    def github_login(self) -> str:
        return f"{self.first_name}-{self.last_name}".lower().replace(" ", "-")

    def slack_handle(self) -> str:
        return f"{self.first_name}.{self.last_name}".lower()


DEPARTMENTS = (
    "Engineering",
    "Security",
    "Platform",
    "Data",
    "Sales",
    "Support",
    "Finance",
    "People",
)

_FIRST_NAMES = (
    "Grace",
    "Alan",
    "Ada",
    "Katherine",
    "Edsger",
    "Barbara",
    "Donald",
    "Margaret",
    "Tim",
    "Radia",
    "Leslie",
    "Vint",
    "Shafi",
    "Frances",
    "Ken",
    "Dennis",
    "Jean",
    "Anita",
    "Hedy",
    "Annie",
    "Mary",
    "Evelyn",
    "Adele",
    "Carol",
    "Sophie",
    "Marian",
    "Joan",
    "Kathleen",
    "Erna",
    "Ida",
    "Milly",
    "Thelma",
    "Nadia",
    "Omar",
    "Priya",
    "Ravi",
    "Sofia",
    "Tomas",
    "Ingrid",
    "Yusuf",
    "Chidi",
    "Mei",
    "Lars",
    "Amara",
    "Diego",
    "Freya",
    "Hiro",
    "Zara",
    "Nils",
    "Oona",
    "Paulo",
    "Rin",
    "Selin",
    "Tariq",
    "Ulla",
    "Viktor",
    "Wren",
    "Xime",
    "Yara",
    "Zeno",
    "Bo",
    "Cleo",
    "Dara",
    "Esme",
)

_LAST_NAMES = (
    "Hopper",
    "Turing",
    "Lovelace",
    "Johnson",
    "Dijkstra",
    "Liskov",
    "Knuth",
    "Hamilton",
    "Berners-Lee",
    "Perlman",
    "Lamport",
    "Cerf",
    "Goldwasser",
    "Allen",
    "Thompson",
    "Ritchie",
    "Bartik",
    "Borg",
    "Lamarr",
    "Easley",
    "Jackson",
    "Granville",
    "Goldstine",
    "Shaw",
    "Wilson",
    "Rejewski",
    "Clarke",
    "Antonelli",
    "Hoover",
    "Rhodes",
    "Koss",
    "Estrin",
    "Okafor",
    "Haddad",
    "Nair",
    "Iyer",
    "Moreno",
    "Novak",
    "Lindqvist",
    "Rahman",
    "Eze",
    "Chen",
    "Andersen",
    "Diallo",
    "Ramos",
    "Olsen",
    "Tanaka",
    "Farah",
    "Berg",
    "Kelly",
    "Costa",
    "Sato",
    "Demir",
    "Aziz",
    "Salo",
    "Petrov",
    "Ashby",
    "Reyes",
    "Haddon",
    "Vargas",
    "Lund",
    "Marek",
    "Nyari",
    "Quill",
)

# Fixed cast members that the shipped fixtures and docs/demo.md already name.
# Keeping them stable means an operator who knows the demo does not have to
# relearn it, and existing docs stay accurate.
_ANCHORS: tuple[Persona, ...] = (
    Persona(
        key="grace",
        first_name="Grace",
        last_name="Hopper",
        email=f"grace@{PRIMARY_DOMAIN}",
        department="Security",
        archetype=Archetype.ADMIN_NO_MFA,
    ),
    Persona(
        key="ada",
        first_name="Ada",
        last_name="Lovelace",
        email=f"ada@{PRIMARY_DOMAIN}",
        department="Engineering",
        archetype=Archetype.ADMIN,
    ),
    Persona(
        key="alan",
        first_name="Alan",
        last_name="Turing",
        email=f"alan@{PRIMARY_DOMAIN}",
        department="Platform",
        archetype=Archetype.STAFF,
    ),
    Persona(
        key="katherine",
        first_name="Katherine",
        last_name="Johnson",
        email=f"katherine@{PRIMARY_DOMAIN}",
        department="Data",
        archetype=Archetype.DORMANT,
    ),
    Persona(
        key="former",
        first_name="Edsger",
        last_name="Dijkstra",
        email=f"former@{PRIMARY_DOMAIN}",
        department="Engineering",
        archetype=Archetype.DEPROVISIONED_ADMIN,
    ),
    Persona(
        key="contractor",
        first_name="Barbara",
        last_name="Liskov",
        email=f"contractor@{VENDOR_DOMAIN}",
        department="Engineering",
        archetype=Archetype.EXTERNAL,
    ),
    Persona(
        key="partner-lead",
        first_name="Radia",
        last_name="Perlman",
        email=f"partner-lead@{VENDOR_DOMAIN}",
        department="Platform",
        # A partner engineer Slack correctly restricts to a guest account --
        # and who is an administrator everywhere else. Neither console shows
        # both halves.
        archetype=Archetype.ADMIN,
        guest_in=frozenset({"slack"}),
    ),
    Persona(
        key="svc-backup",
        first_name="Backup",
        last_name="Service",
        email=f"svc-backup@{PRIMARY_DOMAIN}",
        department="Platform",
        archetype=Archetype.SERVICE_ACCOUNT,
    ),
    Persona(
        key="svc-deploy",
        first_name="Deploy",
        last_name="Bot",
        email=f"svc-deploy@{PRIMARY_DOMAIN}",
        department="Platform",
        archetype=Archetype.SERVICE_ACCOUNT,
        tenants=frozenset({"github", "okta"}),
    ),
)

# Roughly how the generated tail is distributed. Weighted so the demo looks like
# a real org -- mostly ordinary staff, a credible number of admins, and a thin
# tail of the things that open findings.
_TAIL_WEIGHTS: tuple[tuple[Archetype, int], ...] = (
    (Archetype.STAFF, 58),
    (Archetype.ADMIN, 11),
    (Archetype.ADMIN_NO_MFA, 4),
    (Archetype.DORMANT, 7),
    (Archetype.DEPARTED, 5),
    (Archetype.EXTERNAL, 11),
    (Archetype.SERVICE_ACCOUNT, 4),
)


def _tenants_for(rng: random.Random, archetype: Archetype) -> frozenset[str]:
    """Which tenants a generated persona appears in.

    Deliberately not uniform: an org where everyone is in all three apps has no
    "who is in GitHub but not Okta" story, which is half of what the cross-app
    graph is for.
    """
    if archetype is Archetype.EXTERNAL:
        # Guests land in one or two collaboration tools, never the IdP.
        return frozenset(rng.sample(["github", "slack"], rng.choice([1, 2])))
    if archetype is Archetype.SERVICE_ACCOUNT:
        return frozenset(rng.sample(["github", "okta"], rng.choice([1, 2])))
    roll = rng.random()
    if roll < 0.45:
        return frozenset({"github", "slack", "okta", "google_workspace"})
    if roll < 0.60:
        return frozenset({"slack", "okta", "google_workspace"})
    if roll < 0.72:
        return frozenset({"github", "okta", "google_workspace"})
    if roll < 0.82:
        return frozenset({"github", "slack", "okta"})
    if roll < 0.90:
        # In the directory and in mail, but no engineering or chat tooling.
        return frozenset({"okta", "google_workspace"})
    if roll < 0.96:
        return frozenset({"okta"})
    # Mail-only: a real shape, and the one that makes "no Okta account" a
    # finding rather than an artifact.
    return frozenset({"google_workspace"})


def build_roster(*, size: int = 100, seed: int = DEFAULT_SEED) -> list[Persona]:
    """Deterministic roster of `size` personas, anchors first.

    Emails are unique by construction: a name collision falls back to a
    numbered local part rather than silently producing two people who the
    identity graph would collapse into one.
    """
    if size < len(_ANCHORS):
        raise ValueError(f"roster size must be >= {len(_ANCHORS)} anchors, got {size}")

    rng = random.Random(seed)
    people: list[Persona] = list(_ANCHORS)
    used_emails = {p.email for p in people}
    used_keys = {p.key for p in people}

    archetypes: list[Archetype] = []
    for archetype, weight in _TAIL_WEIGHTS:
        archetypes.extend([archetype] * weight)

    while len(people) < size:
        first = rng.choice(_FIRST_NAMES)
        last = rng.choice(_LAST_NAMES)
        archetype = rng.choice(archetypes)
        domain = VENDOR_DOMAIN if archetype is Archetype.EXTERNAL else PRIMARY_DOMAIN

        local = f"{first}.{last}".lower()
        email = f"{local}@{domain}"
        suffix = 2
        while email in used_emails:
            email = f"{local}{suffix}@{domain}"
            suffix += 1
        used_emails.add(email)

        key = email.split("@", 1)[0]
        while key in used_keys:
            key = f"{key}-{rng.randrange(1000, 9999)}"
        used_keys.add(key)

        people.append(
            Persona(
                key=key,
                first_name=first,
                last_name=last,
                email=email,
                department=rng.choice(DEPARTMENTS),
                archetype=archetype,
                tenants=_tenants_for(rng, archetype),
            )
        )

    return people


def roster_for(personas: list[Persona], tenant: str) -> list[Persona]:
    """The subset of the roster that exists in one tenant."""
    return [p for p in personas if tenant in p.tenants]
