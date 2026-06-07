# PyTCP — Source File Authoring Rule

This rule codifies the general source-file mechanics every
non-test Python file in PyTCP MUST follow: file skeleton,
copyright block, module docstring, imports, naming,
formatting, inline comments, source docstrings.

It is the **general** rule that applies across all three
subpackages (`packages/net_addr/net_addr/`, `packages/net_proto/net_proto/`, `packages/pytcp/pytcp/`). Two
companion rules layer protocol- and runtime-specific
conventions on top:

- [`net_proto.md`](net_proto.md) —
  the per-protocol six-file pattern (`*Header` /
  `*HeaderProperties` / `*Base` / `*Parser` / `*Assembler` /
  `*Errors`) plus options, enums, dataclass shape, validation
  helpers, error templates, buffer/struct conventions.
- [`pytcp.md`](pytcp.md) — the `packages/pytcp/pytcp/`
  runtime: `Subsystem`, packet-handler mixins, BSD socket
  facade, sysctl registry, stack configuration.

Language-feature and type-annotation rules live separately:

- [`python_features.md`](python_features.md) — Python
  3.10–3.14 features PyTCP MUST use; forbidden pre-3.10
  fallbacks.
- [`typing.md`](typing.md) — annotation discipline, generics,
  `Self` / `@override`, `cast` and `# type: ignore` policy.

Test files are governed by
[`unit_testing.md`](unit_testing.md) and
[`integration_testing.md`](integration_testing.md).

---

## 1. Runtime dependencies

The stack itself has **zero runtime dependencies outside the
standard library**. The only permitted non-stdlib import in
non-test source is:

- `click` — used by `net_addr` CLI helpers only, and gated
  behind the optional `PyTCP-net_addr[cli]` extra (lazily
  imported, so importing `net_addr` stays stdlib-only).

(`aenum` was removed: `ProtoEnum` extends unknown wire
codepoints natively via a stdlib `enum.Enum._missing_` hook —
see [`net_proto.md`](net_proto.md) §11.)

If you need anything else at runtime, stop and justify it
before adding it.

Prefer `memoryview` / the buffer protocol for packet data;
never copy bytes you can slice.

Line length is **120** (black / isort configured at 120).

## 2. File skeleton

A `.py` file is either a **library module** (imported only) or
a **script** (has an `if __name__ == "__main__":` block and is
invoked as `./foo.py`). The shebang and executable bit go on
scripts only — per standard Python convention, library modules
carry neither.

Known scripts in this repo: `tests_runner.py` and every file
in `examples/`. Everything under `packages/net_addr/net_addr/`, `packages/net_proto/net_proto/`, or
`packages/pytcp/pytcp/` is a library module.

### 2.1 Library module layout (no shebang)

1. Lines 1–22: the 80-character-wide GPL copyright block (see §3).
2. Blank lines 23 and 24.
3. Lines 25–31: module docstring (see §4).
4. Blank line 32 (single blank after the docstring — black 26's rule).
5. Imports (see §5).
6. Blank line.
7. Module-level constants, including any RFC ASCII diagrams.
8. Blank line.
9. Class / function definitions.

No shebang. No executable bit (`chmod a-x`).

### 2.2 Script layout (shebang + exec bit)

1. Shebang on line 1: `#!/usr/bin/env python3`
2. Blank line 2.
3. Lines 3–24: the GPL copyright block.
4. Blank lines 25 and 26.
5. Lines 27–33: module docstring.
6. Blank line 34 (single blank after the docstring).
7. Imports.
8. Blank line.
9. Module-level constants.
10. Blank line.
11. Function / class definitions, ending with an
    `if __name__ == "__main__":` entry block.

The file must be marked executable (`chmod +x`).

### 2.3 Common rules

No code, comments, or `__all__` between the docstring and the
first import. `__all__` lives **only in package `__init__.py`
files** (see `packages/net_proto/net_proto/__init__.py`); source modules never
declare it.

### 2.4 `__init__.py` is mandatory in every package directory

Every directory that contains `.py` files OR contains a
subdirectory that is part of the package tree MUST carry an
`__init__.py`. **PyTCP uses regular packages everywhere.**
PEP 420 namespace packages are forbidden in the project's
source / test trees.

The top-level package `__init__.py` files
(`packages/net_addr/net_addr/__init__.py`,
`packages/net_proto/net_proto/__init__.py`,
`packages/pytcp/pytcp/__init__.py`) carry the public-API
`__all__` re-exports. **Every other** `__init__.py` is empty
— a zero-byte file whose only role is to make the directory
a regular Python package.

**Why:** PyTCP doesn't use PEP 420's actual feature
(submodules contributed by separate distributions); each
package is monolithic. Namespace packages cost tool-
compatibility friction (notably pyright's PEP 561 `py.typed`
propagation), so the project pays the trivial cost of empty
marker files in exchange for universal tool support and the
convention every major Python project (numpy / pandas /
Django / mypy / pyright / the stdlib) follows.

Anti-pattern — adding a new directory without
`__init__.py`:

```
packages/net_proto/net_proto/protocols/foo/  # NO __init__.py — FORBIDDEN
packages/net_proto/net_proto/protocols/foo/foo__header.py
```

Correct — every directory carries the marker:

```
packages/net_proto/net_proto/protocols/foo/__init__.py  # empty file
packages/net_proto/net_proto/protocols/foo/foo__header.py
```

### 2.4.1 Encapsulated subpackages — narrow carve-out

A subpackage MAY carry a non-empty `__init__.py` when the
subpackage is deliberately encapsulated: it has a single
public symbol (or small symbol set) and every other module
inside it is private implementation that outside code MUST
NOT import directly. In that case `__init__.py` is a tiny
re-export shim, never a code-bearing module:

```python
# packages/pytcp/pytcp/protocols/tcp/session/__init__.py
"""... encapsulation contract docstring ..."""

from pytcp.protocols.tcp.session.tcp__session import TcpSession

__all__ = ["TcpSession"]
```

Rules for this exception:

1. The shim contains **only** the docstring, the canonical
   copyright block, and the re-export(s) + `__all__`. No
   class definitions, no helper functions, no side-effecting
   statements.
2. The subpackage `__init__.py` docstring **MUST** spell out
   the encapsulation contract: which symbol(s) are public,
   that every other module inside the subpackage is private,
   and what test-side reach-throughs (if any) are explicitly
   tolerated.
3. The contract is enforced socially (rule + reviewer
   attention) and by convention; PyTCP does not yet run a
   mechanical "no deep imports from outside the subpackage"
   check. Because the split-class files reach across the
   `_`-prefixed boundary between sibling modules, each carries
   the file-level dual `# pylint: disable=protected-access` +
   `# pyright: reportPrivateUsage=false` suppression — see
   §5.2 for the full protected-access boundary rule.
4. The carve-out is granted **only** when an encapsulation
   payoff exists: outside code already treats the subpackage
   as a black box, the internal layout is genuinely volatile
   (refactor likely), and a search shows no current deep
   imports from outside production code.

Canonical examples (both at
`packages/pytcp/pytcp/protocols/tcp/`):

- **`session/`** — the TcpSession + five collaborator
  subpackage that emerged from the Phase-1..5 god-class
  decomposition (see
  `docs/refactor/tcp_session_decomposition.md`). Outside
  code sees only `TcpSession`; the five collaborator files
  are free to be split / merged / renamed without touching
  any import outside `session/`. Deep-path consumers are
  limited to the collaborator-seam parity tests in
  `tests/integration/protocols/tcp/test__tcp__session__<collab>.py`,
  which exist specifically to test the collaborator
  classes and are tolerated as test-side reach-throughs.
- **`fsm/`** — the per-state TCP finite-state-machine
  handlers and the four event-kind dispatchers. Outside
  code sees only the four dispatch functions
  (`dispatch_packet` / `dispatch_syscall` / `dispatch_timer`
  / `dispatch_icmp`); the dispatch-table module
  (`tcp__fsm`) and the eleven per-state handler modules
  (`tcp__fsm__<state>`) are private to the subpackage. The
  only deep-path consumer is the FSM unit test at
  `tests/unit/protocols/tcp/fsm/test__tcp__fsm.py`, which
  reaches for the `FSM_*_HANDLERS` dispatch dicts to
  exercise the table contents directly.

## 3. Copyright / license block (MANDATORY, verbatim)

The 80-character-wide GPL block below is identical in every
file (opening/closing lines are 80 `#` characters). Do not
shorten, widen, or edit the wording. In library modules it
starts on line 1; in scripts it starts on line 3 (after
shebang + blank line).

```
################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################
```

When copying, verify the width with `awk 'NR==3 {print length($0)}'`
on a known-good file (should print `80`).

## 4. Module docstring

Immediately after the license block (two blank lines), every
module has a triple-quoted docstring in this exact shape:

```python
"""
<one-sentence description of what this module contains>.

<path relative to repo root, forward slashes>

ver 3.0.x
"""
```

- Opening and closing `"""` each on their own line.
- First line is one sentence, period-terminated, starting
  with either `This module contains the ...` (for modules) or
  `This package contains ...` (for `__init__.py` files).
- The relative path uses `/` separators and matches the
  file's real location (e.g.
  `packages/net_proto/net_proto/protocols/udp/udp__header.py`).
- The version string tracks the package version and is
  bumped in lockstep with `pyproject.toml`. Use the current
  value (e.g. `ver 3.0.4`); do not leave `3.0.x` literal.

## 5. Imports

Order (each group separated by one blank line):

1. `from __future__ import annotations` (only when a module
   uses `if TYPE_CHECKING:` imports inside annotations — see
   [`typing.md`](typing.md) §20 for the audit rule).
2. Standard library: plain `import …` lines first, then
   `from … import …` lines.
3. `click` (only in `net_addr`'s CLI helpers, per §1).
4. Local packages in dependency order: `net_addr` →
   `net_proto` → `pytcp`.

Rules:

- **Only absolute imports.** Never `from ..lib import foo`.
- Multi-import from one module uses parentheses, one name per
  line, trailing comma:
  ```python
  from net_proto.lib.int_checks import (
      is_4_byte_alligned,
      is_uint6,
      is_uint16,
      is_uint32,
  )
  ```
  Never backslash-continued.
- Note the spelling `is_4_byte_alligned` (double-l) — it is
  deliberate and consistent across the codebase. Match it;
  do not "correct" it ad hoc.
- `TYPE_CHECKING`-guarded imports +
  `from __future__ import annotations` are **forbidden**
  unless the file has a genuine circular import. See
  [`typing.md`](typing.md) §20 for the audit-the-trio rule.

### 5.1 Cross-module visibility

Each rule below is **MUST**, distilled from real refactors
the `pytcp.lib.neighbor` / `pytcp.stack.sysctl` scaffolding
needed after shipping. The failure mode that motivated each
rule is named in parentheses.

- **Never import a `_`-prefixed name from another module.**
  The leading underscore says "internal to this module." If
  module A is using `from B import _foo`, the right fix is to
  **rename `_foo` to `foo` in B** — it is part of B's public
  surface. Importing across the underscore boundary is a
  classification bug; suppressing it with a wider underscore
  is not. Failure mode: every `*_constants.py` consumer
  reaching into `sysctl._register` / `_is_positive_int` /
  `_finalize_validators`, blurring the public API line until
  the registry could not be refactored without breaking
  importers.

- **Don't `_ = Name` to suppress unused-import warnings.** If
  an import is unused, delete it. The `_ = X` idiom rots —
  six months later the import is still there and nobody knows
  whether to keep it. If a name is "held for future signature
  use," add it when the future arrives.

- **Constants-module imports go at module top, not
  function-local.** See [`pytcp.md`](pytcp.md)
  §2 for the sysctl-backed-constants access pattern.
  Function-local imports re-execute import machinery on every
  call AND defer the constants module's registration
  side-effects until first invocation — meaning the registry
  is empty at boot and operator overrides racing the first
  read hit `KeyError`.

### 5.2 Protected-access boundary (no cross-class private reach-through)

§5.1 governs *importing* a `_`-prefixed name; this section
governs *accessing* a `_`-prefixed attribute or method of
**another class** at runtime (`other_obj._private`). The
underscore means "private to the declaring class." Reaching
across it from a different class is the same classification
bug as the import case, and it is **MUST-not** in production
(non-test) source.

**Why this rule needs to be written down: the lint gate does
not catch it.** mypy — PyTCP's only gated type checker — has
**no private-usage diagnostic at all**; a single leading
underscore is pure convention to it, so `obj._foo` from
outside the class type-checks clean. The only two tools that
flag cross-class private access are **pylint
(`protected-access` / `W0212`)** and **Pyright / Pylance
(`reportPrivateUsage`)** — and pylint is **not** in the
`make lint` gate (gate = codespell + isort + black + flake8 +
mypy). So this boundary is unenforced by CI today and rests
on reviewer attention plus the IDE squiggle. (pylint exempts
same-class access — `other._x` inside `__eq__` where `other`
is the same class is fine and is **not** a violation; this
rule is only about reaching into a *different* class.)

**The three MUST rules:**

1. **A `_`-prefixed method reached from another class →
   rename it public** (drop the underscore). It was always
   part of the class's real surface; the underscore was a
   misclassification. Do not paper over the call site with a
   suppression.

2. **A `_`-prefixed attribute read from another class →
   expose a read-only `@property`.** The Linux-`/proc`-style
   read surface (`handler.interface_mtu`, `handler.ip4_ifaddr`)
   is the boundary; the `_`-attribute stays the storage.

3. **Read-write only when a sanctioned writer genuinely
   exists, and via a named mutator method — never a
   read-write property.** A writable property invites callers
   to mutate the underlying container in place (breaking any
   copy-on-write-under-lock invariant — see
   [`pytcp.md`](pytcp.md)); a `set_mtu()` /
   `assign_ifaddr()` / `remove_ifaddr()` method keeps the
   mutation explicit and lockable. Construction-time
   object-graph wiring (a stack assembler setting a freshly
   built handler's collaborators) uses an explicit
   `attach_*(...)` method or constructor parameter, not a
   reach-in write.

**The one sanctioned exception — a single class split across
files.** When one logical class is deliberately decomposed
into several files (the encapsulated-subpackage pattern of
§2.4.1 — `protocols/tcp/session/`, `protocols/tcp/fsm/`),
the collaborator / per-state files legitimately operate on
the shared instance's private state. Those files carry a
**file-level dual suppression**, placed immediately after
the copyright block and before the module docstring, that
silences **both** offending tools:

```python
################################################################################
##   ... copyright block ...                                                  ##
################################################################################


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false
```

Both lines are **mandatory together** — pylint and Pyright
flag the same access independently, so suppressing only one
leaves the other (the IDE squiggle, typically) live. There
is no repo-level Pyright config; the per-file
`# pyright: reportPrivateUsage=false` comment is what does
the work, so it cannot be omitted. (`reportUnusedExpression=false`
is added on the same line only where the file also has
bare-expression statements, as the `fsm/` files do.)

**Per-line exceptions are a discuss-first corner case, not a
default.** When a genuine cross-class reach-through cannot be
removed (e.g. mirroring a stdlib-internal like
`sock._decref_socketio()` for drop-in parity), the inline
form silences both tools on that line:

```python
result = sock._decref_socketio()  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]
```

Prefer fixing the boundary (rules 1–3) over an inline
suppression; raise the case with the maintainer before
reaching for the comment.

**Tests are exempt.** Cross-class private access in
`*/tests/` is acceptable (the Phase-3 reach-through markers
of CLAUDE.md already sanction it); the dual-suppression and
rename rules above apply to **non-test source only**.

## 6. Source-file docstrings

- **Every module, every class, every method** has a
  docstring. Functions at module scope too (rare; most code
  is method-bound).
- Always triple-quoted `"""…"""`, even for one-liners.
- Format for classes and methods is the multi-line form —
  opening `"""` on its own line, a single sentence on the
  next, closing `"""` on its own line:
  ```python
  def __len__(self) -> int:
      """
      Get the UDP header length.
      """

      return UDP__HEADER__LEN
  ```
  The blank line between the closing `"""` and the first
  statement is mandatory.
- Phrasing:
  - **Classes**: a noun phrase ending in a period.
    `"""The UDP packet header."""`, `"""The UDP protocol base."""`.
  - **Methods**: imperative phrase ending in a period.
    `"""Get the UDP header length."""`, `"""Initialize the
    UDP packet parser."""`.
  - **`__post_init__` / `_validate_*`**: start with `Ensure …`.
  - **Property accessors on `*HeaderProperties`**: exactly
    `Get the <PROTO> header '<field>' field.` — don't
    paraphrase. See
    [`net_proto.md`](net_proto.md)
    §6 for the full property-mixin pattern.
  - **Property accessors on `*OptionsProperties` mixins and
    on `*Options` container classes** (the lookup
    properties that return a specific option from the
    container — both surfaces serve the same role, so the
    same canonical phrasing applies): two forms based on
    what the property returns.
    - **Returns the option object itself** (return type
      `<Proto>Option<Name> | None`): use exactly
      `Get the <PROTO> '<option-name>' option.` The
      trailing `| None` in the return type carries the
      "if present" signal; don't restate it in the
      docstring.
      Example: for `def lsrr(self) -> Ip4OptionLsrr | None`,
      the docstring is `Get the IPv4 'lsrr' option.`
    - **Returns the option's extracted value** (return type
      `Buffer | None`, `int`, `Ip4Mask | None`, etc.): use
      exactly `Get the <PROTO> '<option-name>' option
      value.` Same rule — don't restate the return-type
      semantics in the docstring.
      Example: for
      `def client_id(self) -> Buffer | None`, the
      docstring is `Get the DHCPv4 'client_id' option
      value.`
    Additional context (RFC citation, default-fallback
    note, behavioural caveat) is acceptable on subsequent
    docstring lines; the canonical first line stays
    uniform across the family.
- Module docstrings follow §4 exactly (description + path +
  `ver`).

Test docstrings have a different shape (`Ensure ...` +
`Reference: ...`); see [`unit_testing.md`](unit_testing.md)
§7.

## 7. Naming summary

| Target                          | Pattern                        | Example                                   |
| ------------------------------- | ------------------------------ | ----------------------------------------- |
| Module-level constant           | `PROTO__SUBJECT__FIELD`        | `TCP__OPTION__MSS__LEN`                   |
| Module filename                 | `proto__component.py`          | `tcp__parser.py`, `tcp__option__mss.py`   |
| Class                           | `<Proto><Component>`           | `TcpHeader`, `TcpParser`, `TcpAssembler`  |
| Properties mixin                | `<Proto><Component>Properties` | `TcpHeaderProperties`                     |
| Error class                     | `<Proto>(Integrity\|Sanity)Error` | `TcpIntegrityError`                    |
| Assembler ctor kwarg            | `proto__field`                 | `tcp__sport`, `udp__payload`              |
| Private instance attribute      | `_name`                        | `_header`, `_payload`, `_frame`           |
| Parent-layer input on a parser  | `_parent__field`               | `_ip__payload_len`, `_ip__pshdr_sum`      |
| Private method                  | `_name`                        | `_validate_integrity`, `_parse`           |
| Threading attribute             | `_event__name`, `_thread__name`, `_lock__name` | `_event__stop_subsystem`  |
| Packet handler file             | `packet_handler__proto__dir.py` | `packet_handler__tcp__rx.py`             |

No trailing underscores on public names. Dunder names are
limited to standard Python protocols (`__init__`, `__len__`,
`__str__`, `__repr__`, `__buffer__`, `__post_init__`,
`__eq__`, `__hash__`, `__bytes__`).

The `PROTO__SUBJECT__FIELD` constant pattern (double
underscores encoding hierarchy) applies everywhere:

- Protocol headers: `UDP__HEADER__LEN`, `UDP__HEADER__STRUCT`.
- Protocol options: `TCP__OPTION__MSS__LEN`.
- Stack-wide constants: `STACK__MAC_ADDRESS`,
  `ARP_CACHE__ENTRY_MAX_AGE__SEC`.

## 8. Formatting

- **120-char** hard line limit (black / isort configured at
  120).
- Opening paren on the same line as the callable / class;
  arguments indented 4 spaces; closing paren on its own line
  at the original indent level. Trailing comma on the last
  element of any multi-line call, tuple, list, or dict.
- Bit-field packing uses one operand per line, operator at
  the start of the continuation line, aligned:
  ```python
  self.hlen << 10
  | self.flag_ns << 8
  | self.flag_cwr << 7
  | self.flag_ece << 6
  ...
  ```
  This pattern appears in every header that packs flag bits
  (TCP, IPv4, IPv6). Match it.

f-string mandate, `%` / `.format()` ban, and the walrus
operator are in [`python_features.md`](python_features.md)
§19–§20.

## 9. Inline comments

- Default to **zero inline comments**. Names are the primary
  documentation; docstrings cover intent; the type system
  covers structure.
- Exceptions — write a comment only when it earns its keep:
  1. **RFC packet diagrams** above module constants (see
     [`net_proto.md`](net_proto.md) §3).
  2. **RFC citations** on constants whose value needs a
     source (`# Minimum recommended MSS (RFC 879).`).
  3. **Non-obvious workarounds**, especially when bypassing
     a normal constraint (e.g.
     `# Hack to bypass the 'frozen=True' dataclass decorator`).
  4. **Phase-2 / Phase-3 markers** when a Phase-1
     simplification would foreclose a future-phase upgrade —
     write `# Phase 2: ...` or `# Phase 3: ...` so the
     upgrade path is greppable.
- Never write comments that describe *what* the next line
  does. If the code needs that comment, rename the variable
  or extract the method instead.
- Never reference tickets, PRs, commit hashes, or "added for
  <caller>" in inline comments — that belongs in the commit
  message and rots in source.

## 10. Anti-patterns

General source-file anti-patterns. Protocol-architecture and
stack-runtime anti-patterns live in
[`net_proto.md`](net_proto.md) §17
and [`pytcp.md`](pytcp.md) §6. Language and
typing anti-patterns live in
[`python_features.md`](python_features.md) §22 and
[`typing.md`](typing.md) §23.

- **Relative imports** (`from ..lib import foo`). Always
  absolute.
- **`__all__` in a non-`__init__.py` source module.**
- **PEP 420 namespace package directory** — adding a new
  source directory under `packages/<x>/<x>/` (or
  `examples/`) without an `__init__.py`. See §2.4. Every
  package directory MUST carry an `__init__.py` (empty for
  intermediate dirs; carrying `__all__` re-exports at the
  top-level package).
- **Trailing underscore on a public name** (`type_` is fine
  as a keyword-collision workaround in `socket.__new__`; no
  other uses).
- **Comments that narrate the code** (`# Set sport to 0`)
  instead of explaining a non-obvious *why*.
- **New runtime dependencies outside the stdlib** (plus the
  two allowed by §1).
- **Importing a `_`-prefixed name from another module.**
  Underscore prefix means "internal to this module." If a
  consumer needs the name, rename it to public in the source
  module — don't reach across the underscore boundary. (See
  §5.1.)
- **Accessing a `_`-prefixed attribute / method of another
  class** (`other_obj._private`) in production source.
  mypy does not flag it (only pylint `protected-access` +
  Pyright `reportPrivateUsage` do, and pylint is ungated) —
  but it is still a MUST-not. Rename the method public, or
  expose a read-only `@property` (read-write only via a named
  mutator), per §5.2. The sole exception is a single class
  deliberately split across files, which carries the
  file-level dual `# pylint: disable=protected-access` +
  `# pyright: reportPrivateUsage=false` suppression. Tests are
  exempt.
- **`_ = SomeName` at end-of-file** to silence unused-import
  warnings. Just delete the import.
- **Function-local `from pytcp.lib import foo__constants`
  inside a hot loop method.** The import goes at module top;
  function-local hides registration timing and re-executes
  import machinery on every loop tick. See
  [`pytcp.md`](pytcp.md) §2 for the
  qualified-module-access pattern.
- **Missing module / class / method docstring.** Every
  module, class, and method has one. Use the triple-quoted
  multi-line form per §6.

## 11. Cross-references

- [`net_addr.md`](net_addr.md) — value-type library
  conventions (ABC hierarchy, slot-based value types,
  multi-form `__init__`, equality / hashing, `click` CLI
  helpers).
- [`net_proto.md`](net_proto.md) —
  per-protocol six-file pattern, dataclass shape, validation
  helpers, error templates, buffer/struct conventions.
- [`pytcp.md`](pytcp.md) — `Subsystem`,
  packet handlers, sockets, sysctl framework, stack
  configuration.
- [`python_features.md`](python_features.md) — Python
  3.10–3.14 features; forbidden pre-3.10 fallbacks.
- [`typing.md`](typing.md) — annotation discipline,
  generics, `Self` / `@override`, `cast` and `# type: ignore`
  policy, the forward-reference trio audit.
- [`unit_testing.md`](unit_testing.md) and
  [`integration_testing.md`](integration_testing.md) —
  test-file authoring conventions.
- [`feature_implementation.md`](feature_implementation.md) —
  the tests-first workflow and the modernise-on-touch rule.
