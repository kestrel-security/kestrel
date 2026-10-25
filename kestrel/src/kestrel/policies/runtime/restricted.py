# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""RestrictedPython-backed policy compilation and evaluation."""

from __future__ import annotations

import ast
import copy
import operator
import re
import time
import uuid
from typing import Any

from RestrictedPython import compile_restricted_exec, safe_globals
from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
from RestrictedPython.Guards import (
    full_write_guard,
    guarded_iter_unpack_sequence,
    guarded_unpack_sequence,
    safer_getattr,
)
from RestrictedPython.Guards import (
    safe_builtins as _rp_safe_builtins,
)
from sqlalchemy.orm import Session

from kestrel.db.models.policy import Severity
from kestrel.policies.dataload import LOADERS, RESOURCE_TYPE_TO_FROM_TYPE, load_rows
from kestrel.policies.evidence_baseline import merge_baseline_evidence
from kestrel.policies.identifiers import validate_policy_id
from kestrel.policies.runtime.helpers import POLICY_HELPERS, PolicyDataError
from kestrel.policies.runtime.serialize import row_to_jsonable
from kestrel.policies.runtime.types import (
    CompiledPolicy,
    PolicyCompileError,
    PolicyContract,
    PolicyEvaluationResult,
    PolicyMatch,
)

# Both derived from the loader table so a new resource type is one edit, not
# three that can disagree about what an author may write.
_VALID_RESOURCE_TYPES = frozenset(RESOURCE_TYPE_TO_FROM_TYPE)
_VALID_PROFILES = frozenset({"level_1", "level_2", "monitor"})
_FORBIDDEN_AST_NODES = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)
_DANGEROUS_CALL_NAMES = frozenset({"exec", "eval", "open", "__import__"})
# RestrictedPython: "Line 2: SyntaxError: expected ':' at statement: '...'"
_RP_LINE_RE = re.compile(r"^Line\s+(\d+)\s*:\s*(.*)$", re.IGNORECASE | re.DOTALL)

# Module-level code runs at compile time, in the calling process (the API, for
# validate / test / generate), with no timeout and no memory limit. So the
# module body may only *declare*: constants and functions. Anything that could
# loop or allocate without bound (a `while`, a call, `"a" * 10**9`) is a
# compile error, and logic belongs inside policy(), which only ever runs under
# the configured runtime. With these rules, executing the module costs time and
# memory proportional to the source text.
_LITERAL_WRAPPERS = frozenset({"frozenset", "set", "tuple", "list"})
_NUMERIC_OPS = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod)
_ANNOTATION_NODES = (ast.Name, ast.Constant, ast.Attribute, ast.Subscript, ast.Tuple, ast.Load, ast.BitOr)
_MODULE_RULE = "the module body may only define constants and functions; put logic inside policy()"


def _protected_module_names() -> frozenset[str]:
    """Names the module body may not rebind.

    The static-value check trusts that ``tuple(...)`` and friends are the
    builtins: ``tuple = hash`` followed by ``X = tuple(L40)`` would otherwise
    call hash() on an exponentially nested structure at compile time, in the
    API process. Shadowing a helper or ``time`` is refused for the same
    reason, and underscore names are RestrictedPython's own guards.
    """
    return frozenset(_policy_safe_builtins()) | frozenset(POLICY_HELPERS) | _LITERAL_WRAPPERS | {"time"}


def _is_numeric_expr(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        return _is_numeric_expr(node.operand)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _NUMERIC_OPS):
        return _is_numeric_expr(node.left) and _is_numeric_expr(node.right)
    return False


def _is_static_value(node: ast.expr, *, hashed: bool = False) -> bool:
    """A value whose evaluation cannot loop and costs no more than its source.

    Names are allowed (``ADMINS = BASE_ADMINS``), except where the value gets
    hashed -- set elements, dict keys, set()/frozenset() arguments. There, a
    chain like ``L1 = (L0, L0)`` ... ``L60 = (L59, L59)`` describes an
    exponentially large structure in a few lines, and hashing it would stall
    the process compiling the policy. Inline literals cost at most their
    source size, which the API caps.
    """
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return not hashed
    if isinstance(node, (ast.Tuple, ast.List)):
        return all(_is_static_value(elt, hashed=hashed) for elt in node.elts)
    if isinstance(node, ast.Set):
        return all(_is_static_value(elt, hashed=True) for elt in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is None or _is_static_value(k, hashed=True) for k in node.keys) and all(
            _is_static_value(v, hashed=hashed) for v in node.values
        )
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_static_value(node.operand, hashed=hashed)
    if isinstance(node, (ast.UnaryOp, ast.BinOp)):
        # Arithmetic on numbers only: `12 * 60` is fine, `"a" * 10**9` is not.
        return _is_numeric_expr(node)
    if isinstance(node, ast.Call):
        hashes_args = isinstance(node.func, ast.Name) and node.func.id in ("set", "frozenset")
        return (
            isinstance(node.func, ast.Name)
            and node.func.id in _LITERAL_WRAPPERS
            and not node.keywords
            and len(node.args) <= 1
            and all(_is_static_value(arg, hashed=hashed or hashes_args) for arg in node.args)
        )
    return False


def _is_simple_annotation(node: ast.expr | None) -> bool:
    if node is None:
        return True
    for child in ast.walk(node):
        if isinstance(child, ast.BinOp) and isinstance(child.op, ast.BitOr):
            continue
        if not isinstance(child, _ANNOTATION_NODES):
            return False
    return True


def _module_statement_error(node: ast.stmt) -> str | None:
    """Why a module-level statement is not allowed, or None if it is."""
    if isinstance(node, ast.Pass):
        return None
    if isinstance(node, ast.Expr):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return None  # docstring
        return f"module-level expression; {_MODULE_RULE}"
    if isinstance(node, ast.Assign):
        if not all(isinstance(target, ast.Name) for target in node.targets):
            return f"module-level assignments must bind plain names; {_MODULE_RULE}"
        for target in node.targets:
            if isinstance(target, ast.Name) and (target.id in _protected_module_names() or target.id.startswith("_")):
                return f"module-level assignment must not rebind the builtin or helper {target.id!r}; {_MODULE_RULE}"
        if not _is_static_value(node.value):
            return f"module-level value must be a literal; {_MODULE_RULE}"
        return None
    if isinstance(node, ast.FunctionDef):
        if node.name in _protected_module_names() or (node.name.startswith("_") and node.name != "_"):
            return f"a function must not shadow the builtin or helper {node.name!r}; {_MODULE_RULE}"
        args = node.args
        if node.decorator_list:
            return f"decorators run at load time and are not allowed; {_MODULE_RULE}"
        defaults = [*args.defaults, *(d for d in args.kw_defaults if d is not None)]
        if not all(_is_static_value(d) for d in defaults):
            return f"default argument values must be literals; {_MODULE_RULE}"
        all_args = [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
        annotations = [node.returns, *(a.annotation for a in all_args if a is not None)]
        if not all(_is_simple_annotation(a) for a in annotations):
            return f"annotations must be plain names; {_MODULE_RULE}"
        return None
    return f"module-level {type(node).__name__} statement; {_MODULE_RULE}"


def _compile_error_from_rp_messages(errors: tuple[str, ...] | list[str]) -> PolicyCompileError:
    """Build a PolicyCompileError, pulling line numbers from RestrictedPython messages."""
    line: int | None = None
    parts: list[str] = []
    for raw in errors:
        text = raw.strip()
        match = _RP_LINE_RE.match(text)
        if match:
            if line is None:
                line = int(match.group(1))
            parts.append(match.group(2).strip() or text)
        else:
            parts.append(text)
    message = "; ".join(parts) if parts else "Policy compilation failed"
    return PolicyCompileError(message, line=line)


def _policy_safe_builtins() -> dict[str, Any]:
    builtins = dict(_rp_safe_builtins)
    for name in ("open", "__import__", "exec", "eval"):
        builtins.pop(name, None)
    # RestrictedPython's defaults omit common pure helpers packs need.
    extras = {
        "any": any,
        "all": all,
        "min": min,
        "max": max,
        "sum": sum,
        "list": list,
        "dict": dict,
        "set": set,
        "frozenset": frozenset,
        "enumerate": enumerate,
        "reversed": reversed,
        "filter": filter,
        "map": map,
    }
    for name, value in extras.items():
        builtins.setdefault(name, value)
    return builtins


#: RestrictedPython compiles `x += 1` to `x = _inplacevar_("+=", x, 1)` and
#: leaves the guard to the host. These are the operators Python's augmented
#: assignment can produce; anything else is refused rather than looked up.
_INPLACE_OPERATORS: dict[str, Any] = {
    "+=": operator.iadd,
    "-=": operator.isub,
    "*=": operator.imul,
    "/=": operator.itruediv,
    "//=": operator.ifloordiv,
    "%=": operator.imod,
    "**=": operator.ipow,
    "<<=": operator.ilshift,
    ">>=": operator.irshift,
    "&=": operator.iand,
    "^=": operator.ixor,
    "|=": operator.ior,
    "@=": operator.imatmul,
}


def _inplacevar(op: str, target: Any, value: Any) -> Any:
    fn = _INPLACE_OPERATORS.get(op)
    if fn is None:
        raise SyntaxError(f"unsupported in-place operator: {op!r}")
    return fn(target, value)


def _restricted_namespace() -> dict[str, Any]:
    namespace: dict[str, Any] = dict(safe_globals)
    namespace["__builtins__"] = _policy_safe_builtins()
    namespace["_getattr_"] = safer_getattr
    namespace["_getitem_"] = default_guarded_getitem
    namespace["_getiter_"] = default_guarded_getiter
    namespace["_iter_unpack_sequence_"] = guarded_iter_unpack_sequence
    namespace["_unpack_sequence_"] = guarded_unpack_sequence
    namespace["_write_"] = full_write_guard
    namespace["_inplacevar_"] = _inplacevar
    namespace["time"] = time
    # Shared, reviewed helpers (within_last_days, has_admin_grant, ...) so packs
    # do not each paste their own copy. See kestrel.policies.runtime.helpers.
    namespace.update(POLICY_HELPERS)
    return namespace


def _node_location(node: ast.AST) -> tuple[int | None, int | None]:
    """Return 1-based (line, column) from an AST node when available."""
    line = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    if isinstance(col, int):
        col = col + 1  # ast uses 0-based columns; match SyntaxError.offset
    return (line if isinstance(line, int) else None, col if isinstance(col, int) else None)


def _validate_ast(source_text: str) -> None:
    try:
        tree = ast.parse(source_text)
    except SyntaxError as exc:
        raise PolicyCompileError(
            f"Policy syntax error: {exc.msg}",
            line=exc.lineno,
            column=exc.offset,
        ) from exc

    for statement in tree.body:
        reason = _module_statement_error(statement)
        if reason is not None:
            line, column = _node_location(statement)
            raise PolicyCompileError(f"Policy not allowed: {reason}", line=line, column=column)

    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_AST_NODES):
            line, column = _node_location(node)
            raise PolicyCompileError(
                f"Policy uses forbidden statement: {type(node).__name__} (imports and global/nonlocal are not allowed)",
                line=line,
                column=column,
            )
        if isinstance(node, ast.Call):
            name: str | None = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name in _DANGEROUS_CALL_NAMES:
                line, column = _node_location(node)
                raise PolicyCompileError(
                    f"Policy must not call {name}()",
                    line=line,
                    column=column,
                )


def _normalize_severity(raw: Any) -> str:
    if not isinstance(raw, str):
        raise PolicyCompileError("SEVERITY must be a string")
    value = raw.strip().lower()
    try:
        Severity(value)
    except ValueError as exc:
        allowed = ", ".join(sorted(member.value for member in Severity))
        raise PolicyCompileError(f"Invalid SEVERITY {raw!r} (allowed: {allowed})") from exc
    return value


def _normalize_resource_type(raw: Any) -> str:
    if raw is None:
        return "identity"
    if not isinstance(raw, str):
        raise PolicyCompileError("RESOURCE_TYPE must be a string")
    value = raw.strip().lower()
    if value not in _VALID_RESOURCE_TYPES:
        allowed = ", ".join(sorted(_VALID_RESOURCE_TYPES))
        raise PolicyCompileError(f"Invalid RESOURCE_TYPE {raw!r} (allowed: {allowed})")
    from_type = RESOURCE_TYPE_TO_FROM_TYPE[value]
    if from_type not in LOADERS:
        raise PolicyCompileError(
            f"resource_type {value!r} has no row loader yet (from_type {from_type!r} is not implemented)"
        )
    return value


def _normalize_compliance(raw: Any) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PolicyCompileError("COMPLIANCE must be a dict mapping framework names to control id lists")
    result: dict[str, list[str]] = {}
    for key, controls in raw.items():
        if not isinstance(key, str):
            raise PolicyCompileError("COMPLIANCE keys must be strings")
        if not isinstance(controls, list) or not all(isinstance(item, str) for item in controls):
            raise PolicyCompileError(f"COMPLIANCE[{key!r}] must be a list of strings")
        result[key] = list(controls)
    return result


def _normalize_requires(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise PolicyCompileError("REQUIRES must be a list of capability key strings")
    return tuple(str(item).strip() for item in raw if str(item).strip())


def _normalize_profile(raw: Any) -> str:
    if raw is None:
        return "level_1"
    if not isinstance(raw, str):
        raise PolicyCompileError("PROFILE must be a string")
    value = raw.strip().lower()
    if value not in _VALID_PROFILES:
        allowed = ", ".join(sorted(_VALID_PROFILES))
        raise PolicyCompileError(f"Invalid PROFILE {raw!r} (allowed: {allowed})")
    return value


def _extract_contract(namespace: dict[str, Any]) -> PolicyContract:
    policy_id = namespace.get("POLICY_ID")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyCompileError("POLICY_ID is required and must be a non-empty string")
    try:
        policy_id = validate_policy_id(policy_id.strip())
    except ValueError as exc:
        raise PolicyCompileError(str(exc)) from exc

    severity = _normalize_severity(namespace.get("SEVERITY"))
    resource_type = _normalize_resource_type(namespace.get("RESOURCE_TYPE", "identity"))

    description = namespace.get("DESCRIPTION", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise PolicyCompileError("DESCRIPTION must be a string when set")

    title_raw = namespace.get("TITLE")
    if title_raw is None:
        title = description.strip() or policy_id
    elif isinstance(title_raw, str):
        title = title_raw.strip() or description.strip() or policy_id
    else:
        raise PolicyCompileError("TITLE must be a string when set")

    remediation_raw = namespace.get("REMEDIATION")
    remediation: str | None
    if remediation_raw is None:
        remediation = None
    elif isinstance(remediation_raw, str):
        remediation = remediation_raw
    else:
        raise PolicyCompileError("REMEDIATION must be a string when set")

    compliance = _normalize_compliance(namespace.get("COMPLIANCE"))
    requires = _normalize_requires(namespace.get("REQUIRES"))
    profile = _normalize_profile(namespace.get("PROFILE"))

    policy_fn = namespace.get("policy")
    if not callable(policy_fn):
        raise PolicyCompileError("policy(resource) function is required")

    evidence_fn = namespace.get("evidence")
    if evidence_fn is not None and not callable(evidence_fn):
        raise PolicyCompileError("evidence(resource) must be callable when defined")

    return PolicyContract(
        policy_id=policy_id.strip(),
        title=title,
        severity=severity,
        resource_type=resource_type,
        description=description,
        remediation=remediation,
        compliance=compliance,
        requires=requires,
        profile=profile,
    )


def _from_type_for_resource_type(resource_type: str) -> str:
    return RESOURCE_TYPE_TO_FROM_TYPE[resource_type]


def attach_related_grants(
    session: Session,
    org_id: uuid.UUID,
    rows: list[dict[str, Any]],
    *,
    grants: list[dict[str, Any]] | None = None,
) -> None:
    """Index grant rows onto identity resources under ``_related.grants``
    so policies can express legacy policy DSL ``exists(grants …)`` checks.

    ``grants`` lets a caller that already loaded the grant family (the
    evaluation row cache) pass it in rather than loading it a second time.
    """
    source = grants if grants is not None else load_rows(session, org_id, "grants")
    by_subject: dict[Any, list[dict[str, Any]]] = {}
    for related in source:
        by_subject.setdefault(related["_subject_id"], []).append(related)
    for row in rows:
        related = row.setdefault("_related", {})
        related["grants"] = by_subject.get(row["_subject_id"], [])


# Back-compat alias for callers that imported the private name.
_attach_related_grants = attach_related_grants


class RestrictedPythonRuntime:
    """Compiles Panther-style Python policies with RestrictedPython."""

    def compile(self, source_text: str) -> CompiledPolicy:
        _validate_ast(source_text)
        byte_code = compile_restricted_exec(source_text, filename="<policy>")
        if byte_code.errors:
            raise _compile_error_from_rp_messages(list(byte_code.errors))
        if byte_code.code is None:
            raise PolicyCompileError("Policy compilation produced no code")

        namespace = _restricted_namespace()
        try:
            exec(byte_code.code, namespace)
        except Exception as exc:  # any module-level failure is a compile error to the author
            raise PolicyCompileError(f"Policy failed to load: {exc}") from exc

        contract = _extract_contract(namespace)
        policy_fn = namespace["policy"]
        evidence_fn = namespace.get("evidence")
        return CompiledPolicy(
            contract=contract,
            policy_fn=policy_fn,
            evidence_fn=evidence_fn,
            source_text=source_text,
        )

    def evaluate_all(
        self,
        compiled: CompiledPolicy,
        session: Session,
        org_id: uuid.UUID,
        rows: list[dict[str, Any]] | None = None,
    ) -> PolicyEvaluationResult:
        if rows is None:
            from_type = _from_type_for_resource_type(compiled.contract.resource_type)
            rows = load_rows(session, org_id, from_type)
            if from_type == "identities":
                attach_related_grants(session, org_id, rows)
        result = PolicyEvaluationResult(
            policy_name=compiled.contract.policy_id,
            evaluated_row_count=len(rows),
        )
        for row in rows:
            # The policy gets its own copy. ``rows`` may come from a RowCache
            # shared by every policy in the pass, and a policy may write to the
            # dict it is handed: without the copy one policy could rewrite the
            # data the next one sees, or retarget ``_subject_id`` to open a
            # finding on a subject of its choosing.
            visible = copy.deepcopy(row)
            try:
                compliant = compiled.policy_fn(visible)
            except PolicyDataError as exc:
                raise PolicyDataError(
                    f"policy() for {compiled.contract.policy_id!r} on subject {row.get('_subject_id')}: {exc}"
                ) from exc
            if not isinstance(compliant, bool):
                raise TypeError(
                    f"policy() for {compiled.contract.policy_id!r} must return bool, got {type(compliant).__name__}"
                )
            if compliant:
                continue
            evidence: dict[str, Any] = {}
            if compiled.evidence_fn is not None:
                evidence = compiled.evidence_fn(visible)
                if not isinstance(evidence, dict):
                    raise TypeError(
                        f"evidence() for {compiled.contract.policy_id!r} must return dict, got {type(evidence).__name__}"
                    )
            evidence = merge_baseline_evidence(compiled.contract.resource_type, row, evidence)
            result.matches.append(
                PolicyMatch(
                    subject_type=row["_subject_type"],
                    subject_id=row["_subject_id"],
                    evidence=row_to_jsonable(evidence),
                )
            )
        return result

    def match_rows(self, compiled: CompiledPolicy, rows: list[dict[str, Any]]) -> list[int]:
        """In-process: no isolation and no time limit. Fine for tests and for
        trusted pack code; the API's default runtime is the subprocess one."""
        matched: list[int] = []
        for index, row in enumerate(rows):
            compliant = compiled.policy_fn(copy.deepcopy(row))
            if not isinstance(compliant, bool):
                raise TypeError(f"policy() must return bool, got {type(compliant).__name__}")
            if not compliant:
                matched.append(index)
        return matched
