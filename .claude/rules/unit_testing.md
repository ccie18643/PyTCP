# PyTCP — Unit Test Authoring Rule

This rule codifies how unit tests are written in PyTCP. It is distilled
from the tests under `packages/net_addr/net_addr/tests/unit/` and
`packages/net_proto/net_proto/tests/unit/protocols/` after they were rewritten to native
`unittest`. Every new test file in this project MUST follow it.

The rule covers: framework, file layout, naming, parameterization
pattern, byte-frame comments, assertion style, and the matrix of test
files required for each protocol.

---

## 1. Framework and toolchain

- Use **native `unittest`** from the standard library. Do **not**
  use `testslide`, `pytest`, or any other test framework.
  `unittest` is stdlib, has no runtime cost, and matches the
  project's zero-runtime-dependency floor.
- Import: `from unittest import TestCase`. For async tests use
  `from unittest import IsolatedAsyncioTestCase`.
- Parameterization uses `parameterized` (already a dev
  dependency) via `@parameterized_class`:
  ```python
  from parameterized import parameterized_class  # type: ignore
  ```
  Zero runtime dependencies outside stdlib still holds for the
  stack itself; `parameterized` is test-only and acceptable.
  For tight in-method parametric loops prefer the stdlib
  `subTest` context manager (see §10b.6).
- **Python 3.14+ floor.** Tests use the same modern Python
  features as production source per
  [`python_features.md`](python_features.md). The
  test-author-relevant subset is §10b below — `@override` on
  every `setUp` / `tearDown`, `enterContext` (3.11+) for
  patches, walrus operator on captured assertions, PEP 604
  unions, lowercase builtin generics. The pre-3.10 `typing`
  forms (`Optional`, `Union`, `List`, `Dict`, `TypeVar`,
  `Generic`) are **forbidden** in test files exactly as they
  are in production.
- **mypy strict applies to tests.** Every test file MUST pass
  `make lint` with no `# type: ignore` unless the ignore
  comment carries an inline justification.
- **Mocking is strict.** See §6a — every `Mock` is spec'd
  with `create_autospec(Cls, spec_set=True)` or
  `patch(..., autospec=True, spec_set=True)`. Bare
  `MagicMock()` / `Mock()` is **forbidden** in new code and
  on-touch in legacy code.
- **Test isolation is enforced.** See §10a — no real time,
  network, filesystem, or threads leaking across tests. The
  full suite is run in alphabetical filename order; no
  individual test may rely on that ordering.

## 2. File structure

Test files are **library modules** — they are imported by
the test runner, not executed directly — so they carry no
shebang and no executable bit. The file-level skeleton:

1. The 80-char `#`-bordered copyright/license block (verbatim,
   no edits) starting on line 1.
2. Module docstring:
   ```python
   """
   <one-sentence description>.

   <relative path from repo root to this file>

   ver 3.0.x
   """
   ```
3. Imports — stdlib first, then `parameterized`, then local
   packages (`net_addr`, `net_proto`, `pytcp`). Multi-import
   from one module uses parentheses, never backslash
   continuation.
4. Module-level constants (baseline frames, shared fixtures).
5. `TestCase` classes.

No `__all__`. No `if __name__ == "__main__":` block. No
shebang. No module-level code between the constants and the
first class.

The pre-3.10 `typing` legacy guards
(`from __future__ import annotations` + `TYPE_CHECKING` +
string-quoted annotations) are **forbidden** in new test
files. PEP 649 (3.14+) handles forward references natively;
see [`python_features.md`](python_features.md) §17.

## 3. File naming and placement

**Canonical pattern (memorise this).** Unit tests for a
source file at `<pkg>/<subpkg>/<source>.py` live at
`<pkg>/tests/unit/<subpkg>/test__<subdir>__<source>.py`.
The filename alone identifies which area of the codebase
and which aspect is under test:

```
SOURCE                                       TEST
────────────────────────────────────────     ─────────────────────────────────────────────────────────────
packages/net_proto/net_proto/protocols/udp/udp__parser.py    →  packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__operation.py
packages/net_proto/net_proto/protocols/udp/udp__header.py    →  packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py
packages/net_proto/net_proto/lib/inet_cksum.py               →  packages/net_proto/net_proto/tests/unit/lib/test__lib__inet_cksum.py
packages/pytcp/pytcp/lib/ip6_source_selection.py         →  packages/pytcp/pytcp/tests/unit/lib/test__lib__ip6_source_selection.py
packages/pytcp/pytcp/socket/raw__socket.py               →  packages/pytcp/pytcp/tests/unit/socket/test__socket__raw__socket.py
packages/pytcp/pytcp/protocols/tcp/tcp__session.py       →  packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__session__lifecycle.py
                                             packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__session__fsm.py
                                             ... (one file per aspect; see §3.3)
```

Rules:

- Files go under `<package>/tests/unit/…` mirroring the source layout.
  For a protocol at `packages/net_proto/net_proto/protocols/<proto>/`, tests live at
  `packages/net_proto/net_proto/tests/unit/protocols/<proto>/`. For a subpackage like
  `packages/net_proto/net_proto/lib/` or `packages/pytcp/pytcp/socket/`, tests live at
  `<package>/tests/unit/<subpkg>/`.
- Double-underscore separators, same as source files.
- **Subdirectory prefix**: when the source subpackage is **not** the
  protocol-specific tree (`protocols/<proto>/`), the test filename
  carries an extra leading segment naming the subpackage, so the
  filename alone states which area of the codebase is under test:

  | Source location                       | Test filename pattern                         |
  | ------------------------------------- | --------------------------------------------- |
  | `packages/net_proto/net_proto/protocols/<proto>/*.py`    | `test__<proto>__<component>__<aspect>.py`     |
  | `packages/pytcp/pytcp/protocols/<proto>/*.py`        | `test__<proto>__<source>__<aspect>.py`        |
  | `<pkg>/lib/*.py`                      | `test__lib__<source>.py`                      |
  | `packages/pytcp/pytcp/socket/*.py`                   | `test__socket__<source>.py`                   |

  Examples: `test__lib__inet_cksum.py`, `test__lib__proto_parser.py`,
  `test__socket__raw__socket.py`,
  `test__tcp__session__lifecycle.py` (a `packages/pytcp/pytcp/protocols/tcp/`
  source file). The one accepted exception is the stutter case
  `test__socket__socket_id.py` (source file `socket_id.py` already
  contains the subdir name) — still prefix it; do not drop the
  leading `socket__` to avoid the stutter.

  Tests for `packages/pytcp/pytcp/protocols/<proto>/*.py` source files live
  under `packages/pytcp/pytcp/tests/{unit,integration}/protocols/<proto>/`
  mirroring the source layout. Every test directory is a
  regular package: an empty `__init__.py` lives at every
  level (see [`source_files.md`](source_files.md) §2.4).

- **Protocol aspect splits**: for per-protocol files under
  `packages/net_proto/net_proto/protocols/<proto>/`, per-aspect splitting is mandatory:

  | Source artifact          | Test file                                                            |
  | ------------------------ | -------------------------------------------------------------------- |
  | Header dataclass         | `test__<proto>__header__asserts.py`                                  |
  | Assembler construction   | `test__<proto>__assembler__asserts.py` *(if any kwargs asserts)*     |
  | Assembler operation      | `test__<proto>__assembler__operation.py`                             |
  | Parser integrity checks  | `test__<proto>__parser__integrity_checks.py`                         |
  | Parser sanity checks     | `test__<proto>__parser__sanity_checks.py`                            |
  | Parser operation         | `test__<proto>__parser__operation.py`                                |
  | Each option (if any)     | `test__<proto>__option__<name>.py`                                   |
  | Options container        | `test__<proto>__options.py`                                          |

  Examples: `test__udp__header__asserts.py`,
  `test__tcp__parser__integrity_checks.py`,
  `test__tcp__option__mss.py`.

- **Large non-protocol source splits**: if a single source file is
  large enough to warrant splitting (e.g. `packages/pytcp/pytcp/socket/tcp__session.py`),
  fan out by aspect after the `test__<subdir>__<source>` prefix:
  `test__socket__tcp__session__enums.py`,
  `test__socket__tcp__session__lifecycle.py`,
  `test__socket__tcp__session__syscalls.py`,
  `test__socket__tcp__session__fsm.py`. Pick aspect names that
  describe the behavioral surface (`enums`, `lifecycle`, `syscalls`,
  `fsm`) — not implementation-phase names that might collide with
  Python dunders (avoid `init`, prefer `lifecycle` or `construction`).

- Class naming: `Test<Component>[__<Variant>]`. Method naming:
  `test__<proto>__<component>[__<aspect>]`. No trailing underscores.
  No dunder test names.

## 4. Parameterization pattern (canonical)

Use `@parameterized_class` with a list of dicts — one dict per case.
Every dict uses the **same key set** across a test class:

```python
@parameterized_class(
    [
        {
            "_description": "Human-readable summary of this case.",
            "_args": [...],            # optional positional args for setUp
            "_kwargs": {...},          # optional kwargs for setUp
            "_mocked_values": {...},   # optional (external state stubs)
            "_results": {...},         # expected outputs keyed by aspect
        },
        ...
    ]
)
class TestFooBar(TestCase):
    """
    <one-line purpose>.
    """

    # Declare every parametrized attribute as a class annotation so
    # mypy strict mode accepts field access in the test methods.
    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the SUT from '_args' / '_kwargs'.
        """
        ...

    def test__proto__aspect(self) -> None:
        """
        Ensure <behavioral guarantee>.
        """
        ...
```

Guidelines:

- The class-level type annotations for `_description`, `_args`,
  `_kwargs`, `_results`, `_mocked_values` are **required** — without
  them mypy strict will fail on `self._args`.
- One behavioral guarantee per test method. Do not pack unrelated
  asserts into one test. Split by aspect (`__len__`, `__str__`,
  `__repr__`, `__bytes__`, each property, each flag path).
- `_results` is always a `dict[str, Any]` keyed by the aspect name.
  The key name is usually the dunder or property under test
  (`"__bytes__"`, `"__repr__"`, `"sport"`, `"header"`, `"payload"`).
- Prefer one parametrized `TestCase` for the happy path and
  separate unparametrized `TestCase`s for corner cases (defaults,
  boundary-accepted values, misc functions like `Tracker`).

## 5. Byte-frame annotation rule (MANDATORY)

Every raw-byte frame in a test fixture carries a structured comment
explaining each field. The comment lives **immediately above the bytes
literal** and is written in the same style across the repo:

```python
# UDP wire frame (8 bytes, header-only):
#   Bytes 0-1 : 0x3039 -> sport=12345
#   Bytes 2-3 : 0xd431 -> dport=54321
#   Bytes 4-5 : 0x0008 -> plen=8 (header-only)
#   Bytes 6-7 : 0xfb8c -> cksum (valid for init=0)
_BASELINE_FRAME = b"\x30\x39\xd4\x31\x00\x08\xfb\x8c"
```

Or, for protocol-level summaries (ARP, Ethernet):

```python
# ARP (Ethernet/IPv4)
#   Hardware type : 0x0001 (Ethernet)
#   Protocol type : 0x0800 (IPv4)
#   HLEN / PLEN   : 6 / 4
#   Operation     : 1 (Request)
#   Sender MAC    : 02:00:00:00:00:91
#   Sender IP     : 10.0.1.91
#   Target MAC    : 00:00:00:00:00:07
#   Target IP     : 10.0.1.7
#
#   Summary       : Unicast ARP request — "Who has 10.0.1.7? Tell 10.0.1.91."
```

Rules:

- Byte ranges use `Bytes A-B` (or `Byte A` for single bytes).
- Hex constants in the comment match the actual bytes exactly. Pad to
  full field width (`0x0008`, not `0x8`).
- If a test deliberately breaks a field to trigger an integrity/sanity
  branch, the comment calls that out in parentheses (e.g.
  `plen=7 (integrity violation: < 8)`, `cksum (intentionally wrong)`).
- For payload fixtures that repeat (`b"X" * 65527`), the comment
  describes the pattern in words (`65527 bytes of 'X'`).
- When you **review** or **move** an existing frame, re-verify the
  comment still matches byte-for-byte. Stale comments are worse than
  no comments.

## 6. Assertion style

All assertions include a descriptive `msg=` argument — no bare
`assertEqual(a, b)`. The message explains the guarantee, not the
mechanics, and interpolates the parametrized `_description` when
inside a `@parameterized_class` test so failures pinpoint the case:

```python
self.assertEqual(
    udp_parser.header,
    self._results["header"],
    msg=f"Unexpected parsed header for case: {self._description}",
)
```

For single-case tests, the message still describes the invariant:

```python
self.assertEqual(
    len(buffers[0]),
    UDP__HEADER__LEN,
    msg="UdpAssembler.assemble must append the 8-byte fixed header first.",
)
```

For `assertRaises`, capture the exception and assert on the full
error message text:

```python
with self.assertRaises(UdpIntegrityError) as error:
    UdpParser(self._packet_rx)

self.assertEqual(
    str(error.exception),
    f"[INTEGRITY ERROR][UDP] {self._error_message}",
    msg=f"Unexpected integrity-error message for case: {self._description}",
)
```

The error-message prefix is always the canonical `[CATEGORY][PROTO] `
form the protocol's `*Error` class produces (e.g.
`[SANITY ERROR][UDP] `, `[INTEGRITY ERROR][TCP] `). Do **not** hand-roll
the prefix in test fixtures.

**Argument ordering.** `assertEqual(actual, expected, msg=...)`
is the canonical form — actual first, expected second. The
unittest convention is `assertEqual(first, second)` with
historically symmetric meaning, but PyTCP fixes the convention
so failure diffs read consistently across the codebase. Same
for `assertIs`, `assertGreater`, etc.

**Pick the tightest assertion.** Use the most specific
assertion method available — not just `assertEqual`:

| Use | When |
|---|---|
| `assertEqual(a, b, msg=)` | values must be equal by `==` |
| `assertIs(a, b, msg=)` | values must be the *same object* (enums, sentinels) |
| `assertIn(a, container, msg=)` | membership test |
| `assertIsNone(x, msg=)` | `x is None` (NOT `assertEqual(x, None)`) |
| `assertIsInstance(x, T, msg=)` | type check |
| `assertGreater(a, b, msg=)` | `a > b` (NOT `assertTrue(a > b)`) |
| `assertAlmostEqual(a, b, msg=)` | floats with default 7-digit tolerance |
| `assertRaises(Exc) as ctx:` | exception type + message capture |
| `assertCountEqual(a, b, msg=)` | unordered sequence equality |

Prohibited:

- **`assertTrue(a == b)`** — use `assertEqual(a, b, msg=...)`.
- **`assertTrue(x is None)`** — use `assertIsNone(x, msg=...)`.
- **`assertTrue(x > y)`** — use `assertGreater(x, y, msg=...)`.
- **`assertFalse(...)`** for anything other than a genuine
  boolean — pick the inverse positive form.
- **`assertEqual(a, b)`** without `msg=` in new code.
- **`assert ...`** (Python's `assert` statement) inside test
  bodies — use `self.assert*` so the failure message and
  context surface to the runner. `assert` is acceptable inside
  test *helpers* that narrow types for mypy.
- **Bare `assertRaises(Exc)`** without capturing — every raise
  test MUST assert on the message text, not just the type.
- **Parentheses around a single string literal in a dict
  value:**
  ```python
  # Bad
  "__repr__": ("UdpHeader(sport=0, dport=0, plen=0, cksum=0)"),
  # Good
  "__repr__": "UdpHeader(sport=0, dport=0, plen=0, cksum=0)",
  ```
  The parenthesized form is a leftover from multi-line string
  concatenation — drop them when the value fits on one line.
- **Bare `mock.assert_called()`** without `_once_with` /
  `_with` — see §6a.4.

Prefer `!r` inside f-string assertion messages for values
(`Got: {value!r}`). For multi-value diagnostic context use the
f-string `=` debug form: `f"Got: {value=}, {expected=}"`.

## 6a. Mocking discipline (MANDATORY)

Every `Mock` instance in a PyTCP test MUST be spec'd. Bare
`MagicMock()` / `Mock()` is **forbidden** because a typo or
signature mismatch on a mock attribute silently passes —
defeating the purpose of the test. Two canonical spelled-out
forms cover every case the project needs.

### 6a.1 `create_autospec(Cls, spec_set=True)` for owned fixtures

When the test constructs the mock directly (in `setUp` or as
a module-level helper):

```python
from unittest.mock import create_autospec
from pytcp.lib.tx_ring import TxRing

@override
def setUp(self) -> None:
    self._tx_ring = create_autospec(TxRing, spec_set=True)
    self._tx_ring.enqueue.return_value = None
```

`spec_set=True` MUST be present. Without it, callers can
*write* to attributes that the real class does not define —
the bare `spec=` only prevents reads. `spec_set=True` locks
both directions.

### 6a.2 `patch(..., autospec=True, spec_set=True)` for context-managed patches

Use the 3.11+ `TestCase.enterContext()` helper to register
the patcher and its automatic cleanup in one line — this is
the preferred modern form for new tests:

```python
@override
def setUp(self) -> None:
    self._tx_ring = self.enterContext(
        patch.object(stack, "tx_ring", autospec=True, spec_set=True),
    )
    self._log = self.enterContext(patch("pytcp.lib.log"))
    self._handler = _StubHandler()
```

`enterContext` runs the cleanup via `addCleanup`
automatically; no manual `patcher.start()` /
`addCleanup(patcher.stop)` pair is needed.

**Migration state.** The existing PyTCP test corpus still
uses the legacy manual form:

```python
@override
def setUp(self) -> None:
    self._log_patch = patch("pytcp.socket.udp__socket.log")
    self._log_patch.start()
    self.addCleanup(self._log_patch.stop)
```

Both forms are correct; `enterContext` is shorter and
harder to get wrong. New tests use `enterContext`. Existing
tests migrate to `enterContext` on touch (per the
modernise-on-touch rule in
[`feature_implementation.md`](feature_implementation.md) §4)
— do not file dedicated sweeps.

### 6a.3 Forbidden mock patterns

- **Bare `MagicMock()` / `Mock()`** with no spec.
- **`patch("module.func")`** without `autospec=True`. mypy
  cannot type-check the resulting mock, and signature drift
  in the real `func` silently leaves the mock accepting any
  arguments.
- **`patch.object(target, attr, MagicMock())`** passing a
  pre-built bare mock as the replacement. Use `autospec=True`
  in the patcher itself.
- **`return_value=` chains without verification.** A
  `mock.method.return_value = X` line configures the mock but
  does not assert the method was called. Pair every non-trivial
  `return_value` with an `assert_called_once_with(...)` or
  equivalent assertion in the test body.
- **Decorator-style `@patch` chains.** Use `enterContext`
  inside `setUp` instead — the decorator form injects mocks
  as positional arguments which is fragile when the chain
  grows.
- **Patching at module scope.** All `patch` calls go inside
  `setUp` (or per-test in the body); never at module load
  time.

### 6a.4 Assertions on mock state

Pick the strictest assertion form:

```python
# Strongest — checks count AND arguments
self._tx_ring.enqueue.assert_called_once_with(eth_packet)

# Acceptable when the count is intentionally flexible
self.assertEqual(
    self._tx_ring.enqueue.call_count,
    2,
    msg="enqueue must be called once per fragment.",
)
self.assertEqual(
    self._tx_ring.enqueue.call_args_list,
    [call(frag_1), call(frag_2)],
    msg="enqueue must be called with each fragment in order.",
)

# Forbidden — too loose
self._tx_ring.enqueue.assert_called()
self.assertTrue(self._tx_ring.enqueue.called)
self.assertEqual(self._tx_ring.enqueue.call_count, 1)  # without args check
```

`assert_called_once_with` is the canonical form. `assert_any_call`,
`assert_has_calls` are acceptable when the call ordering is
genuinely flexible — never as a "I don't want to write the
exact args" shortcut.

### 6a.5 `side_effect` for sequenced returns

When a mocked method must return different values across
calls:

```python
# Good
self._nd_cache.find_entry.side_effect = [None, GATEWAY_MAC, None]

# Or a callable for state-driven returns
def _fake_find(*, ip6_address: Ip6Address) -> MacAddress | None:
    return _LOOKUP_TABLE.get(ip6_address)

self._nd_cache.find_entry.side_effect = _fake_find
```

The callable form is strongly preferred over a hard-coded
list when the lookup is keyed by argument value — failures
point at the missing key rather than at "ran off the end of
the list" which is opaque.

## 7. Test-method docstrings

> **MANDATORY — before committing any test file (new or
> modified), run the §7.2 self-audit grep below and fix every
> reported violation.** A test docstring that violates §7 is a
> blocker for the commit, not a polish task. This rule was
> repeatedly ignored historically; the audit step is now
> non-negotiable.

**Canonical shape (memorise this).** Every test method has a
docstring with exactly three parts in this order:

```python
def test__udp__parser__integrity__zero_cksum_skips_validation(self) -> None:
    """
    Ensure a frame with cksum=0 bypasses checksum validation
    even when the bytes would otherwise not sum to zero.

    Reference: RFC 768 (UDP checksum optional / zero bypass).
    """
```

The three parts:

1. **Description**, opening word `Ensure`, stating the
   behavioural guarantee from the caller's perspective.
2. **Blank line.**
3. **One `Reference:` line per cited RFC clause** in the form
   `Reference: RFC <number> §<section> (<short description>).`

Rules (each is **MUST** / **MUST NOT**, not SHOULD):

- The description describes *what* is guaranteed, never *how* the
  code is tested.
- **MUST NOT put RFC citations inline in the description.** Strings
  like `"Per RFC X §Y ..."`, `"per RFC X §Y ..."`, `"RFC X §Y: <fact>"`,
  or `"RFC X §Y figure N"` inside the description are forbidden —
  the trailing `Reference:` line is the canonical citation.
  Duplicating it in prose is the exact failure mode that motivated
  this rule. If you need to state the formula, write the formula
  itself (`"alpha_cubic * bytes_acked / cwnd"`), not the citation.
- **MUST** include a `Reference:` line. Pure plumbing tests with no
  RFC clause use one of the two acceptable fallback citations:
  - `Reference: PyTCP test infrastructure (no RFC clause).`
  - `Reference: RFC 9293 §3.9 (User/TCP interface).` (for socket-API
    plumbing).
- A test that pins behaviour from multiple RFCs uses one
  `Reference:` line per clause, in citation-precedence order:

  ```python
  Reference: RFC 9293 §3.10.7.4 (R2 abort emits RST).
  Reference: RFC 1122 §4.2.3.5 (R2 ≥ 100 s retransmit abort).
  ```

  **MUST NOT** bundle multiple citations into a single
  `Reference:` line — each clause gets its own line so the citation
  is greppable.

- **MUST NOT** leave `[FLAGS BUG]` markers in docstrings. Tests-
  first development may temporarily mark expected failures, but the
  marker MUST be stripped before the corresponding fix commit
  lands. A docstring containing `[FLAGS BUG]` is a cleanup-debt
  indicator, not a long-lived annotation.

Class docstrings are one noun phrase
(`"The UDP packet parser sanity checks tests."`). Class-level
docstrings MAY contain RFC references (existing canonical files
like `test__tcp__cwnd.py` use `"RFC 5681 §3.1 slow-start branch:
..."` as the noun phrase); this rule applies only to test-method
docstrings.

### 7.1 RFC clause picker (TCP)

When citing a TCP RFC clause, pick the most specific clause that
covers the behaviour under test. Common picks (the canonical
inventory, distilled from the SHIPPED docstring-citation pass):

| RFC | Section | When to cite |
|---|---|---|
| RFC 9293 | §3.1 | Header format, wire-level field layout |
| RFC 9293 | §3.3.2 | FSM state machine dispatch |
| RFC 9293 | §3.4 | Sequence-number arithmetic, modular comparison |
| RFC 9293 | §3.4.1 | ISS selection (also RFC 6528) |
| RFC 9293 | §3.5 | Connection establishment (active/passive open) |
| RFC 9293 | §3.6 | Closing a connection |
| RFC 9293 | §3.7.1 | MSS option |
| RFC 9293 | §3.7.4 | Nagle algorithm |
| RFC 9293 | §3.7.5 | IPv6 jumbograms |
| RFC 9293 | §3.8.4 | Keep-alive |
| RFC 9293 | §3.8.6.1 | Zero-window probing (persist timer) |
| RFC 9293 | §3.8.6.2 | Silly Window Syndrome avoidance |
| RFC 9293 | §3.9 | User/TCP interface (OPEN / SEND / RECEIVE / CLOSE / ABORT / STATUS) |
| RFC 9293 | §3.10.7.x | Per-state segment processing |
| RFC 1122 | §4.2.2.2 | PSH on last segment of write |
| RFC 1122 | §4.2.2.16 | Robustness against shrinking windows |
| RFC 1122 | §4.2.3.2 | Delayed-ACK |
| RFC 1122 | §4.2.3.3 | Receiver SWS avoidance |
| RFC 1122 | §4.2.3.4 | Nagle (Minshall variant) |
| RFC 1122 | §4.2.3.5 | R2 ≥ 100 s retransmit abort |
| RFC 1122 | §4.2.3.6 | Keep-alive |
| RFC 1337 | §3 | TIME-WAIT assassination mitigations |
| RFC 2018 | §2 | SACK-Permitted bilateral negotiation |
| RFC 2018 | §3 | SACK option wire format / scoreboard |
| RFC 2675 | §5 | IPv6 jumbogram MSS=65535 wire signal |
| RFC 2883 | §3-§5 | DSACK detection / generation |
| RFC 5681 | §3.1 | Slow-start vs CA, RTO ssthresh halving |
| RFC 5681 | §3.2 | Fast-retransmit / fast-recovery |
| RFC 5681 | §4.2 | Immediate ACK on OOO segment |
| RFC 5961 | §3 | RST acceptability hardening |
| RFC 5961 | §4 | SYN-in-synchronized challenge ACK |
| RFC 5961 | §5 | ACK acceptability (snd_una − max_window) |
| RFC 6298 | §2.1-§2.5 | RTO computation (initial, sample, EWMA, clamps) |
| RFC 6298 | §3 | Karn's algorithm |
| RFC 6298 | §5.5 | Binary backoff |
| RFC 6298 | §5.7 | Idle reset + SYN-RTO floor |
| RFC 6528 | §3 | Hash-based ISS generator |
| RFC 6582 | §3 | NewReno step-3b deflation |
| RFC 6675 | §3 | IsLost / NextSeg |
| RFC 6675 | §4 | Pipe / FlightSize estimate |
| RFC 6691 | §2 | MSS calculation from MTU |
| RFC 6928 | §2 | Initial Window of 10 segments |
| RFC 7323 | §2 | WSCALE bilateral negotiation |
| RFC 7323 | §3 | Timestamps option wire format |
| RFC 7323 | §4 | RTTM via TSecr |
| RFC 7323 | §4.3 | _ts_recent update |
| RFC 7323 | §5 | PAWS |

Prefer RFC 9293 over the obsolete 793 / 1122-TCP-section / 5961
when 9293 incorporates them; cite 1122 / 5681 / 5961 / 6298 / 7323
separately when the clause is not folded into 9293 or you want the
historical reference. UDP / IP / ARP / ICMP tests cite their own
canonical RFCs (768, 791, 826, 792, 4443, etc.).

### 7.2 Pre-commit self-audit (MANDATORY)

> Run this audit immediately after writing or modifying any test
> file, AND again before `git commit`. It takes <1 second and
> catches every common violation. Treat any non-empty output as a
> blocker for the commit.

The canonical audit script (paste verbatim, edit `FILES`):

```bash
python3 << 'EOF'
import re, sys
from pathlib import Path

FILES = [
    "packages/pytcp/pytcp/tests/unit/protocols/<proto>/test__<...>.py",
    "packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<...>.py",
    # ... list every test file you wrote or modified.
]

violations = []
for path in FILES:
    text = Path(path).read_text()
    for m in re.finditer(
        # Tolerant signature pattern: matches both the single-line
        # `def test__x(self) -> None:` and the multi-line
        # `def test__x(\n    self,\n) -> None:` forms. A naive
        # `\(self\)` pattern silently skips every multi-line
        # signature, under-reporting violations (this is a real
        # historical miss — see the audit-G sweep notes).
        r'def (test__\w+)\([^)]*\)\s*->\s*None:\s*\n\s*"""(.*?)"""',
        text, re.DOTALL,
    ):
        name, body = m.group(1), m.group(2)
        if "Reference:" not in body:
            violations.append(f"{path}::{name} — missing 'Reference:' line")
        if not re.search(r'^\s+Ensure ', body):
            violations.append(f"{path}::{name} — must start with 'Ensure '")
        if "[FLAGS BUG]" in body:
            violations.append(f"{path}::{name} — contains '[FLAGS BUG]' marker")
        # Strip trailing Reference: lines, then scan description.
        desc = re.sub(r'\n\s*Reference:.*', '', body, flags=re.DOTALL)
        for pat in (r'[Pp]er RFC \d', r'RFC \d+\s*§', r'RFC \d+\s+figure'):
            if re.search(pat, desc):
                violations.append(
                    f"{path}::{name} — inline RFC citation in description "
                    f"(see §7 'no inline citation'); pattern={pat!r}"
                )

for v in violations:
    print(v)
sys.exit(1 if violations else 0)
EOF
```

What it checks (mirroring §7's MUST / MUST NOT rules):

1. Every test method has a `Reference:` line.
2. Every test method's description starts with `Ensure `.
3. No `[FLAGS BUG]` markers remain.
4. No inline `Per RFC X §Y`, `RFC X §Y`, or `RFC X figure N`
   citation in the description text (the trailing `Reference:`
   line is the canonical home for the citation).

If the script prints any line, fix that docstring before
committing. Do not bundle docstring fixes into "follow-up"
commits — fix them in the same commit that introduces the test.

The CUBIC project's docstring fixes (commit `d4a53b3b`) are the
canonical example of what NOT to ship: three test method
docstrings had inline `RFC X §Y` text that duplicated the
trailing `Reference:` line, surviving review until a separate
audit caught them.

## 8. Required test matrix per protocol

For every protocol `<proto>` under `packages/net_proto/net_proto/protocols/`, the
following files must exist and cover the following aspects. Miss none
of these; coverage targets 100% line/branch for the component under
test.

### 8.1 `test__<proto>__header__asserts.py`

Tests the frozen dataclass `__post_init__` assertions.

- `setUp` builds a valid default `self._kwargs` dict that would
  construct a minimal valid header.
- First test: `test__<proto>__header__default_accepted` — constructs
  once and asserts `len(header) == <PROTO>__HEADER__LEN` so a
  regression that makes the baseline invalid is caught immediately.
- One test per field per assert branch. For integer fields this is
  always `__under_min` and `__over_max`, using
  `UINT_8__MIN - 1`, `UINT_8__MAX + 1`, etc. from `net_proto`.
- For enum fields: `__not_<TypeName>` — passes a string or other wrong
  type, asserts message contains `Got: {type(value)!r}`.
- Assertion message template:
  ```
  The '<field>' field must be a <N>-bit unsigned integer. Got: {value!r}
  The '<field>' field must be a <EnumName>. Got: {type(value)!r}
  ```
  Match the source's assert message text verbatim.

### 8.2 `test__<proto>__assembler__asserts.py`

Only needed when the assembler performs its own constructor asserts
beyond what the header validates (e.g. TCP options length).

- `defaults_accepted` test first.
- One test per assert branch — under/over/misaligned/invalid-shape.
- Also cover boundary-accepted values (e.g. `options_len exactly
  TCP__OPTIONS__MAX_LEN`) so a tightening regression is caught.

### 8.3 `test__<proto>__assembler__operation.py`

Parametrized happy-path matrix covering at minimum:

- Minimum (zero/empty payload) and maximum (UINT16 ceiling) field
  values.
- A typical realistic packet.
- Protocol-specific edge cases (e.g. cksum=0 for UDP, every TCP flag
  combination that matters).

Per case, `_results` must include **every** observable aspect:

```python
"_results": {
    "__len__": <int>,
    "__str__": <str>,
    "__repr__": <str>,
    "__bytes__": <bytes>,          # annotated with a wire-frame comment
    # Every property the assembler exposes:
    "sport": 12345,
    "dport": 54321,
    "plen": 24,
    "cksum": 0,
    "header": UdpHeader(...),
    "payload": b"...",
}
```

One `test__<proto>__assembler__<aspect>` method per key. Additionally:

- `test__<proto>__assembler__assemble` — appends to a `list[Buffer]`
  and verifies concatenation equals `__bytes__`.
- `test__<proto>__assembler__assemble__buffer_layout` — checks the
  exact number of buffers appended and the length of each, so
  downstream code relying on positional indexing is safe.

A separate unparametrized `TestFooAssemblerMisc` covers:

- `echo_tracker` plumbing (assembler stores the provided Tracker).
- `defaults` — constructing with no kwargs yields a minimal valid
  object.

### 8.4 `test__<proto>__parser__integrity_checks.py`

Two test classes:

1. **Parametrized rejection matrix** — one case per integrity branch in
   the parser's `_validate_integrity()`. Use one shared baseline
   frame constant at module level; each case either:
   - reuses the baseline and perturbs `_ip__payload_len` /
     `_ip__pshdr_sum`, or
   - supplies a bespoke frame with one field deliberately broken
     (always annotated in the comment: `plen=7 (integrity violation)`).

   The test body asserts `assertRaises(<Proto>IntegrityError)` and
   matches the full formatted error message, including the canonical
   `[INTEGRITY ERROR][<PROTO>] ` prefix.

2. **Boundary-accepted class** — `Test<Proto>ParserIntegrityBoundary`
   — constructs the shortest frame that passes every integrity check
   and asserts it parses. Guards against future tightening that would
   silently reject the minimum-valid packet.

Stub the IP layer with `SimpleNamespace`:

```python
from types import SimpleNamespace

self._packet_rx = PacketRx(self._frame_rx)
self._packet_rx.ip = SimpleNamespace(  # type: ignore[assignment]
    payload_len=self._ip__payload_len,
    pshdr_sum=self._ip__pshdr_sum,
)
```

The UDP/TCP parsers only read `ip.payload_len` and `ip.pshdr_sum`, so
the stub is sufficient and the tests are IPv4/IPv6 agnostic. State
this in the class docstring.

### 8.5 `test__<proto>__parser__sanity_checks.py`

Same shape as integrity checks, but every case is a structurally valid
frame that violates a logical invariant (`sport == 0`,
`dport == 0`, etc.). Asserts on `<Proto>SanityError` with the
`[SANITY ERROR][<PROTO>] ` prefix.

### 8.6 `test__<proto>__parser__operation.py`

Parametrized happy-path matrix, similar shape to the assembler
operation matrix. Per case, `_results` must include:

```python
"_results": {
    "header": <ProtoHeader>(...),
    "payload": b"...",
    # plus each parser property the protocol exposes
}
```

Methods on the class cover:

- `test__<proto>__parser__header` — decoded header equals expected.
- `test__<proto>__parser__payload` — extracted payload equals expected.
- `test__<proto>__parser__packet_rx_<proto>` — parser installs itself
  on `packet_rx.<proto>`.
- `test__<proto>__parser__packet_rx_frame_advanced_past_header` —
  verifies `packet_rx.frame` has been advanced to the payload.
- Any additional fields exposed by the parser's `*HeaderProperties`
  mixin.

### 8.7 Options tests (protocols with TLV options, e.g. TCP)

One file per option type (`test__<proto>__option__<name>.py`). Each
file has typically two `TestCase` classes:

1. `Test<Proto>Option<Name>Asserts` — constructor boundary asserts
   (under_min, over_max for every integer field).
2. `Test<Proto>Option<Name>Assembler` — parametrized matrix of
   `__len__` / `__str__` / `__repr__` / `__bytes__` / property values.
3. Optionally a parser/integrity class per option.

Plus `test__<proto>__options.py` for the options container itself —
covering composition, ordering, length computation, lookup properties
(e.g. `options.mss`), and the integrity rules enforced on the whole
set.

## 9. Production-code fixes

Writing thorough tests routinely surfaces bugs in the protocol
sources. When this happens:

- Keep the fix minimal and targeted.
- Bundle it with the test commit that exercises it.
- In the commit body, list each issue and the fix applied. Example:

  ```
  Add udp parser integrity-check tests

  Bundles a production-code fix for udp__parser.py: the plen
  upper-bound check used `<` where the RFC requires `<=`, which
  rejected maximum-size datagrams. Caught by the new UINT16-ceiling
  parametrized case.
  ```

Typical issues surfaced by this process: incorrect validation bounds,
missing sanity checks, off-by-one parsing, misleading docstrings,
missing `@override`, properties that don't match the field they
claim to expose, style violations against `CLAUDE.md`.

## 10. Workflow

Work one test file at a time. For each file:

1. Read the source under test. Confirm which branches/fields/dunders
   exist.
2. Draft the test file following this rule.
3. Run:
   ```bash
   python -m unittest <path/to/test_file>
   coverage run --source=<source> -m unittest <path/to/test_file>
   coverage report -m
   make lint
   ```
4. Iterate until coverage is 100% for the target component and lint
   is clean.
5. Commit with a focused message; include any production-code fix
   notes in the body.
6. Push/sync before moving to the next file.

## 10a. Test isolation and determinism (MANDATORY)

Every test MUST be deterministic and order-independent. The
full suite (`make test`) is run in alphabetical filename
order, but no individual test may rely on that ordering —
running any single test in isolation must produce the same
result the full-suite run does. Two recurring failure modes
this rule guards against: tests that pass alone but fail in
suite (leaked state from an earlier test), and tests that
pass in suite but fail alone (depending on a side effect of
an earlier test's setup).

### 10a.1 Forbidden runtime dependencies

| Forbidden | Use instead |
|---|---|
| `time.sleep(N)` | `patch("<module>.time.monotonic", return_value=...)` and advance the clock manually |
| `time.time()` direct read | `patch("<module>.time.time", return_value=...)` |
| Real `random` output | `patch("<module>.random.uniform", return_value=...)` or seed with `random.seed(N)` |
| Real socket / TAP / TUN I/O | `create_autospec(TxRing, spec_set=True)` fixture, mock `socket.socket`, etc. |
| Real filesystem writes | `tempfile.TemporaryDirectory` registered via `addCleanup(td.cleanup)` |
| Real DNS / `getaddrinfo` | mock `socket.getaddrinfo` |
| Real `os.urandom` / cryptographic randomness | mock `secrets.token_bytes` / patch the consumer |
| Real environment variables | snapshot/restore `os.environ` |

The general rule: if the test depends on anything outside the
process (clock, network, disk, environment), patch it.

### 10a.2 Module-level state snapshot/restore

If a test mutates module-level state (e.g. attributes on
`pytcp.stack` or `pytcp.stack.sysctl`), the fixture MUST
snapshot the original state and restore it on cleanup.
Otherwise the mutation leaks to subsequent tests and silently
corrupts results.

```python
@override
def setUp(self) -> None:
    self._stack__attr_snapshot = stack.__dict__.copy()
    # ... fixture construction ...

@override
def tearDown(self) -> None:
    stack.__dict__.update(self._stack__attr_snapshot)
    super().tearDown()
```

For sysctl overrides specifically, use the existing
`sysctl_module.override(key, value)` context manager — it
auto-restores on exit:

```python
with sysctl_module.override("icmp6.use_tempaddr", 2):
    result = self._packet_handler._select_ip6_source(...)
```

Or restore module-wide on `tearDown`:

```python
@override
def tearDown(self) -> None:
    sysctl_module.reset_to_defaults()
    super().tearDown()
```

The integration `NetworkTestCase` already snapshots
`stack.__dict__`; new fixtures touching module state MUST
follow the pattern. **Adding module-level state to
`packages/pytcp/pytcp/stack/__init__.py` REQUIRES the same commit to update
`TcpTestCase` `setUp`/`tearDown` (or `NetworkTestCase`
where applicable)** — otherwise the "passes alone, fails in
suite" bug leaks in.

### 10a.3 Subsystem threads

Tests that construct a `Subsystem` subclass (or any class
spawning background threads) MUST ensure the thread is
stopped before the test exits:

```python
@override
def setUp(self) -> None:
    self._cache = NdCache()
    self._cache.start()
    self.addCleanup(self._cache.stop)
```

Use `addCleanup` rather than `tearDown` so the stop is
registered *immediately* after construction — if the test
body raises, the cleanup still fires. The same pattern
applies to any `threading.Thread` started during `setUp` or
in a test body.

For thread-spawning code under test (e.g.
`_claim_ip6_address_async`), patch the thread spawn or wait
for the thread inline with a short timeout. Never let a
daemon thread outlive the test.

### 10a.4 No print, no real log output

Tests MUST NOT emit output to stdout or to the project log
channels. The `make test` run shows progress as `.` per
passing test; spurious output between the dots indicates a
missing log patch. Two canonical forms:

**Module-level silence** (cheapest, applies to every test
in the module):

```python
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL

def setUpModule() -> None:
    stack.LOG__CHANNEL = set()

def tearDownModule() -> None:
    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL
```

**Per-test patch** (when the log call is itself an assertion
target):

```python
@override
def setUp(self) -> None:
    self._log = self.enterContext(patch("pytcp.<module>.log"))
```

Symptom of broken log patching: `make test` output speckled
with `[INET6/.../] - Resolved ...` lines mixed in among the
`.` test progress marks, or `STACK | Initializing ...` lines
from a `stack.init()` call leaking out.

### 10a.5 No shared mutable state between tests

Each `test__*` method gets a fresh fixture via `setUp`. Never:

- Mutate class-level attributes on the SUT type — mutate
  instance state on a fresh fixture.
- Cache expensive setup at class level and mutate it across
  tests. If construction is genuinely expensive, use
  `setUpClass` to build a *read-only* fixture and document
  the read-only contract — but prefer per-test
  reconstruction unless the cost is provably significant.
- Mutate fixture state from a test method and rely on the
  mutation in a sibling method — the test order is not
  guaranteed.

### 10a.6 Test naming for isolation discovery

Use `python -m unittest <single-test>` regularly during
development to catch isolation bugs early. If a test passes
in suite but fails alone, the fixture is depending on a
leaked side effect from earlier in the run. Fix the fixture,
not the test.

## 10b. Modern Python features in tests

Test files follow the same language-feature rules as
production source — see
[`python_features.md`](python_features.md). The subset most
relevant to test authoring is enumerated here so the audit
can short-circuit "is this test using a modern form".

### 10b.1 `@override` on setUp / tearDown / runTest

`unittest.TestCase` declares `setUp`, `tearDown`,
`setUpClass`, `tearDownClass`, `addCleanup`, and others as
parent methods. Every override MUST carry `@override`:

```python
from typing import override

class TestUdpParser(TestCase):
    @override
    def setUp(self) -> None:
        self._frame = _BASELINE_FRAME

    @override
    def tearDown(self) -> None:
        sysctl_module.reset_to_defaults()
        super().tearDown()
```

This is a **mechanical gate, enforced in tests too**: the
`explicit-override` error code is enabled repo-wide in
`pyproject.toml` with **no `*.tests.*` exemption**, so mypy
strict flags any `setUp` / `tearDown` / `setUpClass` /
`tearDownClass` (or any other method overriding a parent)
that is missing `@override`. The decorator is not just
documentation — it turns a mistyped hook name (e.g.
`def tearDwon`, which would silently never run and leak
state) into a type error rather than a latent bug.

Two corollaries the gate enforces:

- **Module-level `setUpModule` / `tearDownModule` are NOT
  decorated.** They are plain module functions that override
  nothing; `@override` on them is itself a type error
  (`misc`). Only `unittest.TestCase` *method* hooks take the
  decorator.
- **A fake / stub class in a test that subclasses a real
  base** (a `ProtoStruct` test double, a `dict` subclass, a
  parser stand-in) carries `@override` on every method that
  overrides the base — `__len__`, `__str__`, `from_buffer`,
  `_validate_integrity`, etc. — exactly as production code
  does.

### 10b.2 `enterContext` / `enterClassContext` / `enterModuleContext` (3.11+)

The 3.11+ `TestCase.enterContext()` method registers a
context manager and schedules its `__exit__` via
`addCleanup` automatically. This is the canonical modern
form for patches and any context-managed fixture:

```python
@override
def setUp(self) -> None:
    self._log = self.enterContext(patch("pytcp.<module>.log"))
    self._tx_ring = self.enterContext(
        patch.object(stack, "tx_ring", autospec=True, spec_set=True),
    )
    self._tmp = self.enterContext(tempfile.TemporaryDirectory())
```

`enterClassContext()` is the equivalent inside `setUpClass`
— shared fixtures whose construction is expensive enough to
amortise across all tests in a class. Use sparingly; per-test
fixtures are easier to reason about.

`enterModuleContext()` for module-level fixtures inside
`setUpModule`. Use very sparingly — module-level state is
the most fragile kind.

The manual form (`patcher = patch(...); patcher.start();
self.addCleanup(patcher.stop)`) is currently the dominant
pattern in the existing PyTCP test corpus. Both forms are
correct; new tests use `enterContext` and existing tests
migrate on touch per the modernise-on-touch rule in
[`feature_implementation.md`](feature_implementation.md) §4
— do not file dedicated sweeps.

### 10b.3 PEP 604 unions and PEP 585 lowercase generics

Test annotations use the same modern syntax as production
code. The pre-3.10 `typing` forms are **forbidden**:

```python
# Good
_args: list[Any]
_kwargs: dict[str, Any]
_results: dict[str, Any]
_mocked_values: dict[str, Any] | None
_callback: Callable[[int, str], None] | None

# Forbidden
from typing import List, Dict, Optional, Tuple
_args: List[Any]
_kwargs: Dict[str, Any]
_results: Optional[Dict[str, Any]]
_pair: Tuple[int, str]
```

The class-level parametrized attribute annotations required
by §4 MUST use the modern forms.

### 10b.4 Walrus in `assertRaises` context managers

The walrus operator pairs naturally with `assertRaises`
when the exception's message is the assertion target:

```python
with self.assertRaises(UdpIntegrityError) as ctx:
    UdpParser(self._packet_rx)

self.assertEqual(
    str(ctx.exception),
    f"[INTEGRITY ERROR][UDP] {self._error_message}",
    msg=f"Unexpected integrity-error message for case: {self._description}",
)
```

### 10b.5 f-string `=` debug form in assertion messages

For multi-value diagnostic context use the f-string `=`
debug form (3.8+):

```python
# Good
self.assertEqual(
    parser.header.plen,
    expected_plen,
    msg=(
        f"Unexpected plen for case: {self._description}. "
        f"Got: {parser.header.plen=}, {expected_plen=}, "
        f"{len(parser._frame)=}"
    ),
)
```

The `=` form emits `name=value` automatically so adding /
removing diagnostic values from a message is one identifier
edit, not a manual string-concat update.

### 10b.6 `subTest` for tight parametric loops

For parametric variations that don't justify a full
`parameterized_class` (small fixed set, single test method,
not reused elsewhere) use the stdlib `subTest` context
manager — every failing iteration surfaces independently
without short-circuiting the loop:

```python
def test__some_property(self) -> None:
    """
    Ensure ...

    Reference: RFC X §Y (...).
    """

    for input_, expected in [
        ("a", 1),
        ("b", 2),
        ("c", 3),
    ]:
        with self.subTest(input=input_):
            self.assertEqual(
                process(input_),
                expected,
                msg=f"process({input_!r}) must return {expected}",
            )
```

When to choose which:

| `parameterized_class` | `subTest` |
|---|---|
| Multiple test methods share the same case list | Single test method has a small fixed variant set |
| Cases carry multiple inputs / expected outputs | One input → one expected output |
| Test discovery + naming benefits ("Test...01...02...03") matter | The iteration is internal to one method |

### 10b.7 PEP 695 generics in fixture base classes

When a test fixture base class is generic over the type
under test, use PEP 695 syntax (3.12+):

```python
class _NeighborCacheFixture[A: Ip4Address | Ip6Address, P = object](TestCase):
    """Shared fixture for both ArpCache and NdCache tests."""

    _cache: NeighborCache[A, P]
    ...
```

The pre-PEP-695 forms (`TypeVar`, `Generic`) are forbidden
exactly as in production.

## 11. Anti-patterns

- Mixing multiple unrelated assertions in one `test__*` method.
- Omitting `msg=` on assertions.
- Parenthesizing single-line string values in dicts.
- Writing byte literals without a matching annotation comment — or
  letting the comment drift out of sync with the bytes.
- Hand-constructing error-message prefixes like `"[UDP] "` instead of
  relying on the `*Error` class's canonical prefix.
- Using `testslide.TestCase` in new code.
- Asserting on private parser internals (`parser._frame`) rather than
  the public contract (`parser.header`, `parser.payload`, properties).
- Coupling a parser test to a specific IP version when the parser only
  reads stub-able IP attributes.
- Losing coverage on the "shortest valid packet" / "minimum accepted"
  boundary by only testing rejection.
- Inlining RFC citations in the docstring description (`"Per RFC X
  §Y ..."`, `"RFC X §Y: <fact>"`) instead of using the canonical
  trailing `Reference: RFC <n> §<s> (<desc>).` line. The trailing
  line is the single source of truth; duplicating it inline is
  forbidden by §7.
- Leaving `[FLAGS BUG]` markers in docstrings of tests that already
  pass. The marker is a tests-first transient — strip it the moment
  the corresponding fix lands.
- Bundling multiple RFC citations into one `Reference:` line. Each
  cited clause gets its own line so the citation is greppable and
  the commit-message audit trail stays clean.
- **Stopping `patch.start()` calls in `tearDown` instead of via
  `self.addCleanup(patch.stop)`.** unittest runs `tearDown`
  BEFORE `doCleanups`, so patches stopped in `tearDown` are dead
  by the time test-level `self.addCleanup(socket.close)` callbacks
  fire — the close-time `log` call leaks straight to stdout. The
  preferred modern form is `self.enterContext(patch(...))` in
  `setUp` (see §6a.2 / §10b.2); the manual fallback (current
  dominant form in the test corpus) is:

  ```python
  def setUp(self) -> None:
      log_patch = patch("pytcp.socket.udp__socket.log")
      log_patch.start()
      self.addCleanup(log_patch.stop)  # runs LAST (LIFO)
      ...
  ```

  Tests that create sockets / subsystems still use
  `self.addCleanup(s.close)`; that callback runs FIRST in cleanup
  while the log patch is still active. Symptom of the broken
  ordering: `make test` output speckled with `[INET4/.../] -
  Closed socket` lines mixed in among the `.` test progress
  marks, or `STACK | Initializing ...` lines from a `stack.init()`
  call inside a test.
- **Bare `MagicMock()` / `Mock()`** instead of
  `create_autospec(Cls, spec_set=True)` (see §6a.1). Always
  forbidden.
- **`patch("module.func")`** without `autospec=True`
  (see §6a.2). The patched callable accepts any signature
  silently, masking signature drift in the real `func`.
- **`assert_called()`** without `_once` / `_with`
  (see §6a.4). Generic "was it called" is too loose — assert
  the exact count and arguments.
- **Decorator-style `@patch` chains** on test methods. Inject
  via `enterContext` inside `setUp` instead (see §6a.2).
- **`time.sleep()`, real `random.uniform()`, real socket I/O**
  in tests (see §10a.1). Patch the source.
- **Module-level mutation of `stack` / `os.environ` / `sys.path`**
  without snapshot/restore (see §10a.2). The leaked state
  produces "passes alone, fails in suite" or vice versa.
- **Background `Subsystem` thread left running** past the
  test (see §10a.3). Always `self.addCleanup(s.stop)`
  immediately after `s.start()`.
- **`assert ...`** (Python `assert` statement) in test body
  (see §6). Use `self.assert*` so the unittest runner
  surfaces failure context.
- **`from __future__ import annotations` + `TYPE_CHECKING` +
  string-quoted annotations** in a new test file (see §2 and
  [`python_features.md`](python_features.md) §17). PEP 649
  (3.14+) handles forward references natively.
- **Pre-3.10 `typing` imports** (`Optional`, `Union`, `List`,
  `Dict`, `Tuple`, `TypeVar`, `Generic`) in tests. Same
  forbidden as production source (see §10b.3).
- **Shared mutable fixture state between sibling test
  methods** (see §10a.5). Each `test__*` gets a fresh
  fixture via `setUp`.

## 12. Reference implementations

When in doubt, mirror the structure of:

- `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__header__asserts.py`
  (header asserts)
- `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__integrity_checks.py`
  (integrity matrix + boundary class, `SimpleNamespace` IP stub)
- `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__sanity_checks.py`
  (sanity matrix)
- `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__parser__operation.py`
  (parser operation matrix)
- `packages/net_proto/net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py`
  (assembler operation matrix + Misc class)
- `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__assembler__asserts.py`
  (assembler constructor asserts with boundary-accepted cases)
- `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__option__mss.py`
  (single option: asserts + assembler matrix)
- `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__options.py`
  (options container composition)
- `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__parser__operation.py`
  (multi-line protocol-summary frame annotation style)
- `packages/net_addr/net_addr/tests/unit/test__ip4_address.py`
  (value-class parameterized matrix: per-property assertions,
  equality/hash/roundtrip blocks split into dedicated TestCases)

These files are the canonical examples. Any deviation from this rule
should be justified by something that appears in one of them — not by
novel patterns introduced in a new file.

## 13. Cross-references

- [`integration_testing.md`](integration_testing.md) — integration-test
  authoring (harness hierarchy on top of `NetworkTestCase`, drive_rx /
  probe / fluent-assert pattern, stat-counter assertions). The
  docstring shape (§7) and §7.2 audit script in this file apply
  identically to integration tests.
- [`python_features.md`](python_features.md) — modern Python 3.10–3.14
  features test files MUST use; forbidden pre-3.10 fallbacks.
- [`typing.md`](typing.md) — annotation discipline, generics,
  `Self` / `@override`, `Protocol` / `TypedDict`, `cast` and
  `# type: ignore` policy. Applies to test files exactly as to
  production source.
- [`feature_implementation.md`](feature_implementation.md) §2 — the
  tests-first workflow that drives every behavioural change. The
  rule that says "write the failing test first" is here.
- [`source_files.md`](source_files.md) — general PyTCP
  source-file conventions. Test files share the file-skeleton,
  copyright-block, and module-docstring conventions.
- [`net_addr.md`](net_addr.md),
  [`net_proto.md`](net_proto.md), and
  [`pytcp.md`](pytcp.md) — what the SUT is shaped like for
  `packages/net_addr/net_addr/`, `packages/net_proto/net_proto/`, and `packages/pytcp/pytcp/` respectively; read
  the relevant one when writing tests for the corresponding
  source files.
