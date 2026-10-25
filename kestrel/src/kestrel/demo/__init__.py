# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""Demo data: fixture generation, drift timeline, and teardown.

Shipped in the wheel (like `kestrel.testing`) so the demo can be driven from a
script or another package, not just the CLI.
"""

# Demo connector instances are labelled so teardown, verification, and the
# operator-side seeder can find exactly the rows `demo up` created and leave a
# real tenant alone. Lives here rather than in the CLI so the library half does
# not have to import the command layer to recognize its own rows.
DEMO_INSTANCE_MARKER = "(demo)"

#: Why a demo instance is never synced from the API or the worker. The demo's
#: tenants come from a generated fixture tree that only `kestrel demo up` and
#: `kestrel demo change` build; a plain fixture sync reads the small bundled
#: sample instead, and deletion detection then removes most of the demo.
DEMO_SYNC_REFUSAL = (
    "This is a demo connector. Its data comes from `kestrel demo up` and `kestrel demo change`; "
    "syncing it here would replace the demo tenant with the small bundled sample."
)


#: Set in a connector instance's config by `kestrel demo up` once it syncs that
#: instance from the generated tree. The "(demo)" label is not enough: `kestrel
#: init --seed` labels its sample GitHub instance the same way, and that one
#: syncs from the shipped fixtures, which is safe to repeat.
DEMO_CONFIG_FLAG = "_demo_generated_fixtures"


def is_demo_instance(config: dict | None, sync_mode: str) -> bool:
    """True for a fixture-mode instance whose data `kestrel demo up` generated."""
    return sync_mode == "fixtures" and bool((config or {}).get(DEMO_CONFIG_FLAG))
