# PyTCP — Typing Rule

This rule codifies how PyTCP code is typed. It covers what
MUST be annotated, what syntax to use, how to type each
language construct, and the common anti-patterns the project
forbids. The companion rules
[`python_features.md`](python_features.md) (the per-PEP
modern-feature inventory) and
[`unit_testing.md`](unit_testing.md) /
[`integration_testing.md`](integration_testing.md) (test
authoring) sit alongside this one and reference back.

Together they form the complete spec. This rule is the
canonical source for typing semantics — when in doubt about
annotation style, signature shape, generic syntax, or where
`# type: ignore` is acceptable, this is the file to read.

---

## 1. Scope and authority

- **Authority.** This rule is normative. `make lint` runs
  mypy in strict mode; any code that violates the rules here
  fails the build.
- **Target.** Python 3.14+. Every typing feature from
  PEP 484 through PEP 750 is unconditionally available;
  there is no fallback for older interpreters.
- **Coverage.** Every PyTCP source file under `packages/net_addr/net_addr/`,
  `packages/net_proto/net_proto/`, `packages/pytcp/pytcp/` (excluding generated and vendored
  code, of which PyTCP has none today) MUST be fully typed.
  Test files under `*/tests/` MUST also pass mypy strict.
- **Authority over runtime cost.** Type annotations are
  zero-cost at runtime per PEP 649 (3.14+ stores them as
  lazy `__annotate__` closures, evaluated only on access).
  There is no "this annotation slows down startup" excuse
  — annotate everything.

## 2. mypy strict configuration

The project enables mypy strict mode. The flags this
translates into (in `pyproject.toml`):

| Flag | Effect |
|---|---|
| `strict = true` | Turns on the whole strict bundle |
| `disallow_untyped_defs` | Every `def` / `async def` MUST have parameter and return annotations |
| `disallow_any_unimported` | An `Any` introduced by a missing-stub import is forbidden |
| `disallow_any_generics` | `list`, `dict`, `set`, `tuple` MUST be parameterised; bare `list` is rejected |
| `check_untyped_defs` | Bodies of untyped defs (rare in this codebase) still type-checked |
| `strict_equality` | `==` between non-overlapping types is rejected |
| `warn_return_any` | A function annotated `-> int` that returns `Any` is flagged |
| `warn_unused_ignores` | Stale `# type: ignore` comments are flagged |
| `warn_redundant_casts` | A `cast(X, value)` where `value` is already `X` is flagged |
| `no_implicit_optional` | A parameter `x: int = None` is rejected — must be `x: int | None = None` |

You don't need to remember the flag names — `make lint` is
the authoritative gate. The list above explains *why* a
particular rule from this file is enforced.

### 2.1 Extra `enable_error_code` codes

On top of the strict bundle, `pyproject.toml` opts into
nine extra error codes via `enable_error_code` — each one
upgrades a latent footgun from silent-pass to build-break:

| Error code | Effect |
|---|---|
| `explicit-override` | A method overriding a parent MUST carry `@override` (§11) — enforced everywhere, tests included |
| `ignore-without-code` | A bare `# type: ignore` is a hard error; the narrow `# type: ignore[code]` form is mandatory (§21) |
| `truthy-bool` | An object with no `__bool__` / `__len__` used in a boolean context (e.g. `if socket :=` where the type can't be falsy) is flagged |
| `truthy-iterable` | An always-truthy iterable used as a plain boolean condition is flagged |
| `redundant-expr` | An `and` / `or` operand that mypy proves constant (always-true / always-false) is flagged |
| `redundant-self` | A redundant `Self`-typed `self` annotation is flagged |
| `possibly-undefined` | A name that may be unbound on some control-flow path (e.g. a `match` with no `case _:` default leaving a variable unset) is flagged |
| `unused-awaitable` | An awaitable whose result is discarded without `await` is flagged |
| `mutable-override` | A subclass narrowing a mutable base attribute's type (covariant override of a settable field) is flagged — applies to test classes too |

`warn_unreachable` and `disallow_any_decorated` are
deliberately **not** enabled: they produce false positives
against the `ProtoEnum` dynamic-`_missing_` `case _:` pattern
and stdlib decorator machinery.

## 3. Annotation discipline — what MUST be annotated

| Construct | Annotation requirement |
|---|---|
| Function / method parameters | All, including `self` is implicit (don't annotate `self`) |
| Function / method return | All, including `-> None` for procedures |
| Class-level attributes | Always (declares the instance attribute even when assigned in `__init__`) |
| Module-level constants | Always (`FOO: int = 42`, not `FOO = 42`) |
| Dataclass fields | Always (the `@dataclass` decorator requires it) |
| Local variables | Only when the inferred type is wrong or surprising |
| Lambda parameters | When mypy can't infer (rare — usually pass the lambda where the expected callable type is known) |

**Local-variable annotations are usually noise.** mypy
infers the type from the right-hand side; an annotation that
just restates the inferred type pollutes the diff. Add a
local annotation only when:

- The right-hand side is a wider type than you want
  (`x: list[int] = []` so `x.append("oops")` fails).
- The variable will be reassigned to a different type later
  and you want to pin the union.
- The right-hand side is `None` and the variable will be
  assigned a real value later (`result: int | None = None`).

## 4. Function signature annotations

### 4.1 Parameter types

Every parameter except `self` / `cls` is annotated. mypy
strict rejects untyped defs.

```python
# Good
def assemble(self, buffers: list[Buffer], /) -> None: ...

def __init__(
    self,
    *,
    udp__sport: int = 0,
    udp__dport: int = 0,
    udp__payload: Buffer = bytes(),
    echo_tracker: Tracker | None = None,
) -> None: ...
```

### 4.2 Return types

Every callable annotates its return type, even `-> None` for
procedures. mypy strict will reject a missing return
annotation even when the body has no `return` statement.

```python
# Good
def _validate_integrity(self) -> None: ...

def find_entry(self, *, ip6_address: Ip6Address) -> MacAddress | None: ...
```

### 4.3 Positional-only `/` and keyword-only `*`

The `/` and `*` separators are part of the API contract;
they are required where the codebase already mandates them:

```python
# Positional-only — buffer / byte / mutated-container args
def assemble(self, buffers: list[Buffer], /) -> None: ...
def from_buffer(cls, buffer: Buffer, /) -> Self: ...
def __init__(self, message: str, /) -> None: ...

# Keyword-only — assembler constructors and any factory where
# named arguments improve call-site clarity
def __init__(
    self,
    *,
    udp__sport: int = 0,
    udp__dport: int = 0,
) -> None: ...

def add_entry(
    self,
    *,
    ip4_address: Ip4Address,
    mac_address: MacAddress,
) -> None: ...
```

Positional-only is mandatory for any parameter that accepts
a buffer, byte string, or container being mutated in place.
Keyword-only is mandatory on assembler constructors and on
any factory where positional construction would be brittle
to field re-ordering.

### 4.4 Default values

The default value must be type-compatible with the
parameter's annotation. mypy strict's `no_implicit_optional`
rejects `x: int = None` — must be `x: int | None = None`:

```python
# Good
def __init__(
    self,
    *,
    echo_tracker: Tracker | None = None,
) -> None: ...

# Forbidden
def __init__(
    self,
    *,
    echo_tracker: Tracker = None,  # mypy: incompatible default
) -> None: ...
```

Mutable default values (`= []`, `= {}`, `= bytes()`) follow
the standard Python advice. For buffer-typed parameters,
`= bytes()` is acceptable as an immutable zero-length
default; for mutable containers use `= None` and bind a
fresh instance in the body.

### 4.5 `*args` / `**kwargs`

Annotate the *element* type, not the container:

```python
# Good
def fire(self, *args: int, **kwargs: str) -> None: ...

# Forbidden — over-annotated
def fire(self, *args: tuple[int, ...], **kwargs: dict[str, str]) -> None: ...
```

PyTCP rarely uses `*args` / `**kwargs` in public APIs — the
codebase prefers explicit keyword-only signatures. If you
find yourself reaching for them, prefer `TypedDict` or a
dataclass instead.

## 5. Variable annotations

### 5.1 Module-level constants

Module-level constants are always typed:

```python
# Good
UDP__HEADER__LEN: int = 8
UDP__HEADER__STRUCT: str = "! HH HH"
TCP__MIN_MSS: int = 536  # Minimum recommended MSS (RFC 879)

# Forbidden
UDP__HEADER__LEN = 8           # mypy strict: missing annotation
```

For multi-element constants the annotation declares the
element type:

```python
# Good
DEFAULT_POLICY_TABLE: tuple[PolicyEntry, ...] = (
    PolicyEntry(network=Ip6Network("::1/128"), precedence=50, label=0),
    ...
)
```

### 5.2 Class-level attribute annotations

Instance attributes declared on a class — whether or not
they have a default — MUST carry an annotation. This pattern
applies to non-dataclass classes that assign attributes in
`__init__`:

```python
# Good — declares the attribute so mypy + IDEs can introspect
class PacketHandlerIp6Tx(ABC):
    if TYPE_CHECKING:
        _interface_layer: InterfaceLayer
        _packet_stats_tx: PacketStatsTx
        _ip6_ifaddr: list[Ip6IfAddr]
        _ip6_multicast: list[Ip6Address]
        _ip6_support: bool
        _interface_mtu: int
```

The `TYPE_CHECKING`-guarded block declares attributes that
the mixin sees from a sibling mixin or that the concrete
subclass populates. Without the declaration, mypy can't
prove the attribute exists.

### 5.3 Dataclass fields

`@dataclass` requires every field to be annotated; mypy
strict and the runtime both agree:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class UdpHeader(ProtoStruct):
    sport: int
    dport: int
    plen: int
    cksum: int
```

For fields with non-trivial defaults that should not appear
in `__repr__` or `__init__`, use `field(...)`:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class ArpHeader(ProtoStruct):
    hrtype: ArpHardwareType = field(
        repr=False,
        init=False,
        default=ArpHardwareType.ETHERNET,
    )
```

### 5.4 Local variables — annotate sparingly

mypy infers local types from the right-hand side. Add a
local annotation only when the inference is wrong, when the
variable is initially `None`, or when the literal needs a
wider type than its initial value suggests:

```python
# Good — initial None, will be reassigned
result: Ip6Address | None = None
for host in candidates:
    if predicate(host):
        result = host
        break

# Good — empty list must accept later .append(int)
buffers: list[Buffer] = []
header.assemble(buffers)

# Bad — annotation just restates the inferred type
count: int = 42        # mypy infers int already; remove the annotation
```

## 6. Union types — `X | Y`

Use PEP 604 union syntax (3.10+) exclusively:

```python
# Good
def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None: ...

type Buffer = bytes | bytearray | memoryview

result: int | str | None = None

# Forbidden — pre-3.10 typing equivalents
from typing import Optional, Union
def find_entry(...) -> Optional[MacAddress]: ...
result: Union[int, str, None] = None
```

The order in a union should be most-common first, with
`None` last when present: `MacAddress | None`,
`bytes | bytearray | memoryview`. There's no semantic
difference, but consistent ordering reads better in diffs.

Never write a union of a single type — `X | X` is just `X`.
Never write `Optional[X | None]` (or its pipe equivalent
`X | None | None`) — once is enough.

## 7. Lowercase builtin generics

Use the lowercase builtins as generic types directly
(PEP 585, 3.9+):

```python
# Good
def assemble(self, buffers: list[Buffer], /) -> None: ...

_entries: dict[A, NeighborEntry[A, P]]
options: tuple[Icmp6NdOption, ...]
flags: set[NudState]
header_struct: type[ProtoStruct]

# Forbidden — never import from typing
from typing import List, Dict, Tuple, Set, FrozenSet, Type
def assemble(self, buffers: List[Buffer], /) -> None: ...
```

`typing.Type[X]` is `type[X]`. `typing.FrozenSet[X]` is
`frozenset[X]`. The `typing` module's uppercase generics
are deprecated runtime aliases — they work but they have no
place in PyTCP source.

`tuple` has two parameterisations:

```python
# Fixed-shape tuple — each position has a type
pair: tuple[int, str] = (1, "a")

# Variable-length homogeneous tuple — like a frozen list
buffers: tuple[Buffer, ...] = (b"a", b"b", b"c")
```

## 8. Type aliases — `type X = ...`

Define aliases with PEP 695 syntax (3.12+):

```python
# Good
type Buffer = bytes | bytearray | memoryview
type SolicitCallback[A: Ip4Address | Ip6Address] = Callable[[A, MacAddress | None], None]
type FlushCallback[P] = Callable[[P, MacAddress], None]

# Forbidden — pre-PEP-695 forms
from typing import TypeAlias
Buffer: TypeAlias = bytes | bytearray | memoryview
Buffer = bytes | bytearray | memoryview  # ambiguous: variable or alias?
```

Aliases are public — they go at module top, after imports
and before classes. The `type` statement creates a true
type alias (not a runtime variable), so it's evaluated
lazily and doesn't break circular references.

Use an alias when:

- The union appears in three or more annotations across a
  module or package.
- The alias name carries semantic intent that a raw union
  doesn't (`type Buffer = ...` says "this is a wire-data
  payload"; `bytes | bytearray | memoryview` doesn't).

Don't alias single-name types (`type MyInt = int` adds
nothing).

## 9. Generic classes and functions — PEP 695

Generic syntax (3.12+) is mandatory for new code:

```python
# Generic class
class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    _entries: dict[A, NeighborEntry[A, P]]

# Generic dataclass
@dataclass(frozen=True, kw_only=True, slots=True)
class NeighborEntry[A: Ip4Address | Ip6Address, P = object]:
    address: A
    queued_packet: P | None = field(default=None)

# Generic function
def first[T](iterable: Iterable[T]) -> T | None:
    for item in iterable:
        return item
    return None

# Generic type alias (also PEP 695)
type FlushCallback[P] = Callable[[P, MacAddress], None]

# Forbidden — pre-PEP-695 TypeVar dance
from typing import Generic, TypeVar
A = TypeVar("A", bound="Ip4Address | Ip6Address")
P = TypeVar("P")
class NeighborCache(Generic[A, P], Subsystem):
    ...
```

`TypeVar`, `Generic`, and `ParamSpec` from `typing` are
forbidden in new code. The only exception is `TypeVar` for
truly esoteric variance cases that PEP 695 doesn't yet
express ergonomically — PyTCP has none today.

### 9.1 Type-parameter bounds vs constraints

PEP 695 supports both bounded and constrained type
parameters:

```python
# Bounded — T must be a SUBTYPE of Ip4Address | Ip6Address
class NeighborCache[A: Ip4Address | Ip6Address]: ...

# Constrained — T must be EXACTLY one of these types
def serialize[T: (int, str, bytes)](value: T) -> bytes: ...
```

Bounds are far more common; constraints are for the rare
case where the implementation differs per type. Both are
acceptable.

### 9.2 Type-parameter defaults (PEP 696, 3.13+)

A type parameter may have a default:

```python
class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    ...

# Consumers may bind both or rely on the default:
cache_no_payload: NeighborCache[Ip4Address] = NeighborCache(...)
cache_typed: NeighborCache[Ip4Address, EthernetAssembler] = ArpCache()
```

Use a default whenever a generic parameter is "new since
the last revision" and you want existing single-parameter
call sites to keep working without an explicit `, object`
sprinkled everywhere.

### 9.3 Constructor calls inside generic classes

When constructing an instance of a generic dataclass inside
a generic method body, mypy can't always infer the type
parameter from the call site. Use explicit generic
subscription:

```python
# Good — inside NeighborCache[A, P]._add_entry
entry = NeighborEntry[A, P](
    address=address,
    mac_address=mac_address,
    state=NudState.REACHABLE,
    ...
)
self._entries[address] = entry

# Bad — mypy defaults P to `object`, then refuses to assign
# the resulting NeighborEntry[A, object] to dict[A, NeighborEntry[A, P]]
entry = NeighborEntry(
    address=address,
    ...
)
```

## 10. `typing.Self`

Use `typing.Self` (PEP 673, 3.11+) for self-returning
classmethods and methods. The compiler resolves it to "the
actual subclass at call time":

```python
# Good
from typing import Self

class Ip6Header(ProtoStruct):
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        fields = struct.unpack(IP6__HEADER__STRUCT, buffer)
        return cls(**dict(zip(_FIELD_NAMES, fields)))

class Ip6IfAddr:
    def with_gateway(self, gateway: Ip6Address) -> Self:
        return type(self)(self._network, self._address, gateway=gateway)
```

**Forbidden** — the pre-PEP-673 TypeVar-bound-to-class dance:

```python
# Forbidden
T = TypeVar("T", bound="Ip6Header")
class Ip6Header(ProtoStruct):
    @classmethod
    def from_buffer(cls: type[T], buffer: Buffer, /) -> T: ...
```

`Self` is for self-referential return types. For other
self-referential annotations (parameters, attributes), use
the class name directly — PEP 649 lazy annotations (3.14+)
makes forward references work without quoting.

## 11. `@override`

Every method that overrides a parent method MUST carry
`@override` (PEP 698, 3.12+):

```python
from typing import override

class UdpHeader(ProtoStruct):
    @override
    def __post_init__(self) -> None:
        assert is_uint16(self.sport), ...

    @override
    def __len__(self) -> int:
        return UDP__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview: ...
```

mypy strict flags missing `@override` decorators
mechanically. The decorator also serves as inline
documentation — "this method is part of the parent's
contract."

### 11.1 When `@override` is wrong

`@override` is for Liskov-compatible overrides. If a
subclass method has a *different signature* (positional →
kw-only with renamed parameters, return type widened,
parameter type narrowed), it's not an override; it's a new
method that happens to shadow. **Do not decorate it with
`@override` and do not suppress the mismatch with
`# type: ignore[override]`.**

Two valid fixes when the subclass needs a different shape:

**Protected-hook pattern.** Rename the parent method with a
leading underscore (`_method_name`) so it's an internal
hook; the subclass provides a new public method that
delegates:

```python
# Parent — internal hook
class NeighborCache[A: Ip4Address | Ip6Address, P = object]:
    def _find_entry(self, address: A) -> MacAddress | None: ...

# Subclass — new public method, NOT an override
class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None:
        return self._find_entry(ip4_address)
```

No `@override`. No `# type: ignore`. The subclass method
exists alongside the parent's protected hook.

**Non-shadowing names.** Pick a name that doesn't collide
with the parent (e.g. `lookup_arp` next to a parent
`find_entry`). The parent's API stays untouched; the
subclass adds a new public method.

If neither fix is workable, the inheritance is wrong —
re-think the design. Don't suppress.

## 12. Protocols — structural typing

`typing.Protocol` (PEP 544) declares a structural type — "any
object with these methods and attributes, regardless of
inheritance." Use it for duck-typed APIs where you don't
control the class hierarchy or where the consumer cares
about behaviour, not class identity:

```python
from typing import Protocol

class HasLen(Protocol):
    def __len__(self) -> int: ...

def total_size(items: Iterable[HasLen]) -> int:
    return sum(len(item) for item in items)
```

Protocols are usually structural — a class doesn't have to
declare it implements `HasLen` to satisfy the type. For
runtime `isinstance(x, HasLen)` to work, decorate the
protocol with `@runtime_checkable`:

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class Closeable(Protocol):
    def close(self) -> None: ...

def maybe_close(obj: object) -> None:
    if isinstance(obj, Closeable):
        obj.close()
```

`@runtime_checkable` is required only when you actually use
`isinstance`. For type-check-only uses, omit it.

PyTCP uses protocols sparingly because its class hierarchies
are deliberate (every protocol header is a `ProtoStruct`
subclass). Protocols are the right tool when you need to
type a callback the caller supplies or a duck-typed external
boundary.

## 13. TypedDict

`typing.TypedDict` (PEP 589) types dict-shaped APIs where a
dataclass would be heavyweight or where the dict comes from
an external source (JSON, TOML, registry entries):

```python
from typing import NotRequired, Required, TypedDict

class SysctlSpec(TypedDict):
    key: Required[str]
    attr: Required[str]
    default: Required[object]
    validator: NotRequired[Callable[[object], None]]
    description: NotRequired[str]
```

`Required` / `NotRequired` (PEP 655, 3.11+) mark per-field
optionality. **Forbidden** — splitting into two TypedDicts
with `total=False`:

```python
# Forbidden
class _SysctlBase(TypedDict, total=False):
    validator: Callable[[object], None]
    description: str

class SysctlSpec(_SysctlBase):
    key: str
    attr: str
    default: object
```

`ReadOnly` (PEP 705, 3.13+) marks a field as immutable
from the consumer side — useful for registry entries that
the consumer must not mutate.

When to use TypedDict vs dataclass:

| Use TypedDict | Use dataclass |
|---|---|
| The dict literal is the natural input form (JSON parse, TOML load) | Constructor lives in PyTCP code |
| Heterogeneous bag of fields with no behaviour | Has methods or invariants |
| External boundary where `**kwargs` flow through | Internal data with `frozen=True` semantics |
| Per-field optionality varies | All fields fixed at construction |

PyTCP uses dataclasses much more than TypedDicts. TypedDicts
appear mostly in the test infrastructure (parameterized_class
case dicts) and the sysctl registry.

## 14. Literal types

`typing.Literal` (PEP 586) types a value as one of a fixed
set of literals. Useful for string / int enums that don't
warrant a full `Enum` class:

```python
from typing import Literal

def set_log_level(level: Literal["debug", "info", "warn", "error"]) -> None: ...

InterfaceKind = Literal["tap", "tun"]

def initialize_interface(kind: InterfaceKind) -> dict[str, Any]: ...
```

For *non-trivial* sets of named codepoints (anything
representing a wire-format value, message type, state, etc.)
PyTCP uses real `Enum` subclasses — see `ProtoEnumByte` /
`ProtoEnumWord`. `Literal` is for ad-hoc tag values where a
full enum class would be ceremony.

`LiteralString` (PEP 675, 3.11+) types a string that must be
a compile-time literal (for SQL / shell escaping). PyTCP has
no current consumer; the form is documented for forward
compat.

## 15. `Final` and `@final`

`typing.Final` (PEP 591) marks a name as **immutable after
its initial binding**. mypy enforces no reassignment.

```python
from typing import Final

# Module-level constant — Final clarifies the assignment is one-shot
MAX_RETRIES: Final[int] = 3
DEFAULT_POLICY_TABLE: Final[tuple[PolicyEntry, ...]] = (...)
```

PyTCP's module-level constants are conceptually `Final` —
the project's coding convention treats ALL_CAPS as
immutable. Explicit `Final` annotation is acceptable but
optional; the ALL_CAPS naming carries the intent.

`@final` (also PEP 591) marks a class or method as **not
subclassable / not overridable**:

```python
from typing import final

@final
class IpProto(ProtoEnumByte):
    """Cannot be subclassed; the IANA IP protocol number space is closed."""
    ...

class TxRing(Subsystem):
    @final
    def enqueue(self, packet: EthernetAssembler) -> None: ...
```

Use `@final` when the class is a sealed leaf in the
hierarchy. Most PyTCP classes are not `@final` — the
codebase makes heavy use of inheritance for protocol
families and packet handlers.

## 16. `@overload`

`typing.overload` declares multiple typed signatures for one
callable. The actual implementation comes after the
overloads:

```python
from typing import overload

@overload
def parse(data: bytes) -> ParsedFrame: ...

@overload
def parse(data: bytes, *, strict: Literal[True]) -> ParsedFrame: ...

@overload
def parse(data: bytes, *, strict: Literal[False]) -> ParsedFrame | None: ...

def parse(data: bytes, *, strict: bool = True) -> ParsedFrame | None:
    """The actual implementation. Not typed by mypy — the overloads above are."""
    ...
```

Use overloads only when the return type depends on the
argument type/value in a way a union can't express. The
single-implementation-with-overloads pattern is the cost; if
the callable is simple, prefer a single signature with a
union return.

PyTCP uses `@overload` rarely. The protocol parser /
assembler factories are good candidates if the API ever
grows that complexity.

## 17. `cast` — the last resort

`typing.cast` is a runtime no-op that tells mypy "trust me,
this value is of type X." Use it **only** when you can prove
the type is correct but mypy cannot:

```python
from typing import cast

# Good — narrowing a Union after a runtime check mypy can't model
def lookup_handler(name: str) -> Handler:
    raw = _registry.get(name)
    if raw is None:
        raise LookupError(name)
    # mypy sees `raw` as object; we know the registry stores Handlers.
    return cast(Handler, raw)
```

**Forbidden uses of cast:**

- **Laundering an `Any`.** If a function returns `Any`, fix
  the function's return type instead of casting at every
  call site.
- **Hiding a Liskov violation.** Never `cast` to make a
  subclass with a different signature look like its parent.
  Refactor (§11.1).
- **Casting in test fixtures to make a typo "work".** If
  you're casting to silence mypy, you're hiding a bug.

mypy's `warn_redundant_casts` flag catches casts that
already match the inferred type. Heed the warning.

### 17.1 `typing.assert_type` for inference debugging

`typing.assert_type(value, T)` is a compile-time assertion
that mypy infers `value` as `T`. Useful for narrowing
debugging and as a regression net in tests:

```python
from typing import assert_type

def test__lookup_narrowed_correctly(self) -> None:
    """..."""
    result = self._registry.lookup("foo")
    assert_type(result, Handler | None)
```

`assert_type` is a runtime no-op. Use it sparingly — once
the narrowing is correct, the assertion is just noise.

## 18. Type narrowing

mypy narrows types based on runtime checks:

```python
def process(value: int | str) -> int:
    if isinstance(value, str):
        return len(value)  # mypy narrows value: str here
    return value             # mypy narrows value: int here

def fetch(name: str) -> Handler | None:
    ...

result = fetch("foo")
if result is None:
    raise LookupError("foo")
# mypy narrows result: Handler from here on
result.do_thing()
```

`isinstance(x, T)`, `x is None`, `x is not None`,
`type(x) is T`, and matched `match`/`case` patterns all
narrow. Use them; don't reach for `cast`.

### 18.1 `TypeGuard` and `TypeIs`

When you have a custom predicate function that mypy can't
narrow from, declare its return type as `TypeGuard[T]`
(PEP 647, 3.10+) or `TypeIs[T]` (PEP 742, 3.13+):

```python
from typing import TypeGuard, TypeIs

# TypeGuard — narrows the positive branch only
def is_ipv4_host(host: object) -> TypeGuard[Ip4IfAddr]:
    return isinstance(host, Ip4IfAddr)

# TypeIs — narrows BOTH branches (3.13+ preferred)
def is_ipv4_host_v2(host: object) -> TypeIs[Ip4IfAddr]:
    return isinstance(host, Ip4IfAddr)

def process(host: Ip4IfAddr | Ip6IfAddr) -> None:
    if is_ipv4_host_v2(host):
        # mypy: host is Ip4IfAddr
        ...
    else:
        # mypy: host is Ip6IfAddr (TypeIs narrows the else branch too)
        ...
```

Prefer `TypeIs` (3.13+) over `TypeGuard` for new
predicates — `TypeIs` narrows both branches, which is what
you almost always want. `TypeGuard` only narrows the
positive branch and leaves the else as the original union.

### 18.2 `assert isinstance` for module-private narrowing

Inside a method body when you know the runtime invariant
holds but mypy can't prove it, `assert isinstance` narrows
and documents the invariant in one line:

```python
def _solicit_ns(self, ip6_address: Ip6Address, cached_mac: MacAddress | None) -> None:
    assert isinstance(stack.packet_handler, (stack.PacketHandlerL2, stack.PacketHandlerL3))
    if cached_mac is None:
        stack.packet_handler.send_icmp6_neighbor_solicitation(...)
```

`assert isinstance` raises `AssertionError` at runtime if
the invariant is violated, so it's not free — but it's the
cleanest narrowing form for module-singleton patterns where
mypy can't prove the type of a global.

## 19. Variance

Generic type parameters are **invariant by default** in
Python. That means:

```python
class Box[T]: ...

def use_int_box(box: Box[int]) -> None: ...

x: Box[bool] = Box()  # bool is a subtype of int
use_int_box(x)         # ERROR — Box[bool] is NOT a Box[int] under invariance
```

For most PyTCP types this is correct — a `list[int]` is not
a `list[object]` because callers might `.append("oops")`.

When you genuinely need variance, PEP 695 supports
explicit covariance / contravariance via `infer_variance=True`
or, in older form, via `TypeVar(..., covariant=True)`.
PyTCP has no current case; covariance is rarely needed
outside of read-only protocols.

The lesson: don't fight invariance. If you need to accept
`Box[int]` and `Box[str]`, use `Box[int | str]` or a
Protocol, not variance gymnastics.

## 20. Forward references and lazy annotations

PEP 649 (3.14+) makes function and class annotations **lazy
by default**. They are stored as `__annotate__` closures and
only evaluated when accessed via `typing.get_type_hints` or
similar. This means:

- A plain `def foo(self) -> Bar: ...` works even when `Bar`
  is defined later in the file or imported only for typing.
- `from __future__ import annotations` is **no longer
  needed** on 3.14+ for forward-reference purposes.
- String-quoted annotations (`def foo(self) -> "Bar":`) are
  **no longer needed** when `Bar` is in runtime scope at
  module load time.

### 20.1 When the legacy trio IS justified

The combination of `from __future__ import annotations` +
`if TYPE_CHECKING:` guarded imports + string-quoted
annotations is justified **only** when there is a genuine
circular import:

```python
# Justified — net_proto.protocols.tcp.tcp__base imports from
# pytcp.lib.X, and pytcp.lib.X imports from tcp__base at
# annotation time. Without the guard, both modules fail to
# load.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from net_proto.protocols.tcp.tcp__base import Tcp

class Foo:
    def bar(self, tcp: Tcp) -> None: ...
```

### 20.2 When the trio is forbidden

When the names involved are runtime-safe to import (no
circular risk), the trio is **forbidden**:

```python
# Forbidden — unnecessary indirection on 3.14+
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from net_addr import Ip4Address, MacAddress
    from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler

class ArpCache(NeighborCache["Ip4Address", "EthernetAssembler"]):
    def find_entry(self, *, ip4_address: "Ip4Address") -> "MacAddress | None": ...
```

Replace with:

```python
# Good — runtime imports, no guard, no quoting
from net_addr import Ip4Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler

class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None: ...
```

### 20.3 Audit the trio together

When removing a `TYPE_CHECKING` guard from a file:

1. Drop `from __future__ import annotations`.
2. Drop the `if TYPE_CHECKING:` block.
3. Move the imports to the module top.
4. **Unquote every annotation** in the file — function
   signatures, attribute annotations, PEP 695 bounds
   (`class Foo[T: Bar]:` not `class Foo[T: "Bar"]:`), and
   `type X = ...` aliases (`type X = Foo | Bar` not
   `type X = "Foo | Bar"`).

Half-converted files (some annotations quoted, some not)
are the worst state — they hide which annotations actually
need lazy evaluation.

### 20.4 Unnecessary string-quoted annotations are FORBIDDEN

A string-quoted annotation — `-> "Foo"`, `x: "Foo"`,
`class C[T: "Foo"]`, `type X = "Foo | Bar"` — is permitted
**only** when the name is genuinely unavailable at runtime,
i.e. it is imported *solely* under `if TYPE_CHECKING:` to
break a real circular import (§20.1). In **every** other case
the quotes are **forbidden**:

- If the name is imported at module top (runtime-available),
  the quotes are pure cruft. PEP 649 (3.14) evaluates
  annotations lazily, so the forward reference is never
  needed — **unquote it.** A name being defined later in the
  same file is *not* a reason to quote either (lazy
  evaluation handles it).
- Do not quote "to be safe" or "to match the line above."
  Quote *only* the names that genuinely cannot be imported at
  runtime; bare everything else.

```python
# Forbidden — 'Ip4Wildcard' is a module-top runtime import; the
# quotes are gratuitous (this was a real bug: it also made pylint's
# unused-import flag the import as unused — see below).
def hostmask(self) -> "Ip4Wildcard | Ip6Wildcard": ...

# Good
def hostmask(self) -> Ip4Wildcard | Ip6Wildcard: ...
```

**Enforced by `make lint`.** The pylint gate runs
`unused-import` (W0611), which flags a runtime import used
**only** inside a string annotation — pylint does not read
names inside quoted annotations, so such an import reads as
"unused." flake8's `F401` *does* read string annotations and
therefore silently misses this; pylint is the backstop. A
`TYPE_CHECKING`-guarded import used in a string annotation is
**not** flagged (the legitimate circular-import case), so the
gate distinguishes the two cleanly and a gratuitous quote
fails CI.

## 21. `# type: ignore` policy

`# type: ignore` is **strongly discouraged**. Every
occurrence in PyTCP source is a tax — it hides a type
issue that future maintainers can't easily reconstruct.

Acceptable uses:

- **Third-party library stubs missing.** When a library
  PyTCP imports lacks a `.pyi` and mypy reports a
  `[import-not-found]`, a single-line ignore with the error
  code is acceptable:
  ```python
  from parameterized import parameterized_class  # type: ignore[import-untyped]
  ```
  The narrow form `# type: ignore[error-code]` is mandatory
  — bare `# type: ignore` is forbidden because it suppresses
  every error on the line, not just the intended one. This is
  now **mechanically enforced**: the `ignore-without-code`
  error code (§2.1) makes a bare `# type: ignore` a hard
  build error, not just a convention.

- **Mypy strict false-positive that has a known issue
  upstream.** Cite the issue:
  ```python
  result = caller(*args)  # type: ignore[arg-type]  # mypy/issues/12345
  ```

**Never acceptable:**

- **`# type: ignore[override]`** — see §11.1.
- **`# type: ignore` to silence a Liskov violation, missing
  return type, or invalid cast.**
- **Bare `# type: ignore`** without an error code.
- **Stale ignores.** mypy's `warn_unused_ignores` flag
  catches these — heed the warning, remove the line.

When in doubt, fix the underlying type issue instead of
suppressing it. If the fix requires a substantial refactor,
file an issue and reference it in the ignore comment.

## 22. Common PyTCP typing patterns

### 22.1 The `Buffer` alias

`Buffer` is the canonical type for any wire-data payload —
`bytes`, `bytearray`, or `memoryview`:

```python
# Defined in packages/net_proto/net_proto/lib/buffer.py
type Buffer = bytes | bytearray | memoryview
```

Every API that accepts or produces wire data uses `Buffer`
instead of re-spelling the union:

```python
# Good
def assemble(self, buffers: list[Buffer], /) -> None: ...

@classmethod
def from_buffer(cls, buffer: Buffer, /) -> Self: ...

def __buffer__(self, _: int) -> memoryview: ...

# Bad — re-spells the union
def assemble(self, buffers: list[bytes | bytearray | memoryview], /) -> None: ...
```

### 22.2 The validator-factory return type

A function that returns a validator callable annotates the
concrete `Callable[[Any], None]` shape, not `Any`:

```python
# Good
def _is_non_negative_int(name: str) -> Callable[[Any], None]:
    def validator(value: Any) -> None:
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"sysctl {name!r} must be non-negative int; got {value!r}")
    return validator

# Bad — opaque return type forces every caller to introspect
def _is_non_negative_int(name: str) -> Any: ...
```

A function with a known callable shape MUST spell it out so
the caller can prove the result is callable.

### 22.3 Generic protocol-handler hierarchies

The `NeighborCache[A, P]` pattern parameterises a base
class over both address type (`A`) and queued-packet type
(`P`), letting the IPv4 and IPv6 adapters bind both:

```python
# Base — generic
class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    _entries: dict[A, NeighborEntry[A, P]]
    _flush_callback: FlushCallback[P] | None

# Adapter — concrete
class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    def _flush_packet(self, packet: EthernetAssembler, mac_address: MacAddress) -> None: ...
```

The adapter binds the queued-packet type, which means
`_flush_packet` takes a concrete `EthernetAssembler` — no
runtime `isinstance` narrowing, no cast, no
`packet: object`.

### 22.4 Frozen dataclass attribute annotations

`@dataclass(frozen=True, kw_only=True, slots=True)` requires
every field to be annotated; the decorator generates the
`__init__`, `__repr__`, `__eq__` based on the annotations.

For fields where the value is computed in `__post_init__`
rather than passed at construction, use
`field(repr=False, init=False, default=...)`:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class ArpHeader(ProtoStruct):
    hrtype: ArpHardwareType = field(
        repr=False,
        init=False,
        default=ArpHardwareType.ETHERNET,
    )
    ptype: EtherType
    hlen: int
    plen: int
    oper: ArpOperation
    sha: MacAddress
    spa: Ip4Address
    tha: MacAddress
    tpa: Ip4Address
```

mypy infers correct types for the generated `__init__` /
`__repr__` from the field annotations.

### 22.5 `NoReturn` for non-returning functions

A function that **never returns normally** — it always
raises, `sys.exit()`s, or loops forever — is annotated
`-> NoReturn` (`typing.NoReturn`, PEP 484). The annotation is
load-bearing, not decorative: mypy strict verifies the body
has no reachable normal exit (a `-> NoReturn` function with
an implicit `return None` path is a type error), and the
caller's flow analysis treats every statement after the call
as unreachable.

The canonical use is a small helper that centralises an
error-raising tail so the surrounding code stays honest about
control flow. `packages/net_addr/net_addr/click_types.py` is the reference: a
`_fail(...) -> NoReturn` wrapper calls `ParamType.fail()`
(itself typed `-> NoReturn` by Click) and ends in
`raise AssertionError("unreachable: ...")`, which makes the
no-return contract provable to **every** linter — so the
`convert()` methods need no trailing `return None` and the
file carries no blanket `# pylint: disable=
inconsistent-return-statements`:

```python
from typing import NoReturn

def _fail[T](
    param_type: ParamType[T],
    /,
    *,
    message: str,
    param: Parameter | None,
    ctx: Context | None,
) -> NoReturn:
    param_type.fail(message=message, param=param, ctx=ctx)
    raise AssertionError("unreachable: ParamType.fail() does not return")
```

The trailing `raise` after a call that is *already*
`NoReturn` is intentional: it is the idiom that makes the
contract provable to flow analysers (notably pylint) that do
not propagate a third-party `NoReturn`, and mypy strict
still accepts the unreachable `raise`.

**`NoReturn` vs `Never`.** `typing.Never` (PEP 484, the
3.11 spelling of the bottom type) is *identical* to
`NoReturn` to the type checker — they are interchangeable.
PyTCP fixes the convention to remove the choice:

- **`NoReturn`** — the **return annotation of a function
  that never returns** (`_fail`, an `_abort` helper, a
  `_raise_*` tail). Reads "calling this does not come back."
- **`Never`** — every **other** bottom-type position: an
  `assert_never(x)` exhaustiveness guard, a parameter that
  can never receive a value, an explicitly-empty type. Reads
  "no value can ever be here."

Never use `Never` as a function's return annotation, and
never use `NoReturn` in a non-return position; mypy accepts
both but the split keeps intent greppable.

## 23. Forbidden patterns roundup

A single index of the typing anti-patterns this rule
forbids. If you find any in source on touch, fix in the
same commit:

| Anti-pattern | Replace with | §  |
|---|---|---|
| `Optional[X]` | `X \| None` | §6 |
| `Union[X, Y]` | `X \| Y` | §6 |
| `List[X]` / `Dict[K, V]` / `Tuple[A, B]` / `Set[X]` / `FrozenSet[X]` / `Type[X]` | `list[X]` / `dict[K, V]` / `tuple[A, B]` / `set[X]` / `frozenset[X]` / `type[X]` | §7 |
| `Foo: TypeAlias = ...` | `type Foo = ...` | §8 |
| `from typing import Generic, TypeVar; class Foo(Generic[T]):` | `class Foo[T]:` | §9 |
| `cls: type[T]` with `TypeVar` | `cls` returning `Self` | §10 |
| Missing `@override` on a parent-method override | add `@override` | §11 |
| `@override` on a method that doesn't share the parent's signature | refactor (protected-hook pattern or non-shadowing name) | §11.1 |
| `# type: ignore[override]` to hide a Liskov mismatch | refactor — never suppress | §11.1 |
| `from __future__ import annotations` + `TYPE_CHECKING` + string-quoted annotations (no real cycle) | drop the trio, unquote everything | §20 |
| String-quoted annotation in a file with no `TYPE_CHECKING` block | unquote | §20 |
| String-quoted PEP 695 bound (`class Foo[T: "Bar"]`) | unquote | §20 |
| `x: int = None` (with no_implicit_optional) | `x: int \| None = None` | §4.4 |
| `def foo(x):` (untyped param) | annotate | §4.1 |
| `def foo() -> ...` missing return annotation | add return annotation | §4.2 |
| `*args: tuple[int, ...]` over-annotation | `*args: int` | §4.5 |
| `T = TypeVar("T", bound="Cls")` | `class Foo[T: Cls]:` | §9 |
| `cast(T, value)` to launder `Any` | fix the function returning `Any` | §17 |
| `cast(T, value)` where mypy can already infer `T` | drop the cast (warn_redundant_casts) | §17 |
| Bare `# type: ignore` | `# type: ignore[error-code]` | §21 |
| `def fn() -> Any:` returning a known callable shape | `Callable[[X], Y]` | §22.2 |
| Re-spelling `bytes \| bytearray \| memoryview` | `Buffer` alias | §22.1 |
| `queued_packet: object` requiring runtime `isinstance` narrowing | parameterise the generic `[..., P = ...]` | §22.3 |
| Blanket `# pylint: disable=inconsistent-return-statements` over a fall-through-into-`fail()` method | `NoReturn` helper ending in `raise` | §22.5 |
| `Never` as a function's return annotation | `NoReturn` | §22.5 |
| `NoReturn` in a non-return position (param / `assert_never`) | `Never` | §22.5 |

## 24. Cross-references

- [`python_features.md`](python_features.md) — per-PEP
  modern-feature inventory. Where this rule says "use
  PEP X feature", that file documents the feature itself.
- [`unit_testing.md`](unit_testing.md) §10b — typing rules
  in test files (`@override` on setUp / tearDown, PEP 604
  unions, PEP 585 lowercase generics, no pre-3.10 `typing`
  imports).
- [`integration_testing.md`](integration_testing.md) §2 —
  same typing rules apply to integration tests.
- [`feature_implementation.md`](feature_implementation.md) §3
  — modernise legacy typing forms on touch; the
  pre-commit checklist gates `make lint` (mypy strict).
- [`source_files.md`](source_files.md) — general PyTCP
  source-file conventions (file skeleton, imports, naming).
- [`net_addr.md`](net_addr.md) — value-type ABC chain and
  PEP 695 generics on `IpNetwork[A, M]` / `IfAddr[A, N, O]`;
  `typing.Self` for self-returning factory methods.
- [`net_proto.md`](net_proto.md) —
  the dataclass shape (`frozen=True, kw_only=True,
  slots=True`), parser / assembler / error-class patterns
  rely on the typing rules in this file.
- [`pytcp.md`](pytcp.md) — the `Subsystem`
  base and packet-handler mixin composition that consume
  PEP 695 generics and `@override`.
- mypy strict configuration: see `pyproject.toml`.
- CPython "What's New" for the per-version typing additions:
  [3.10](https://docs.python.org/3/whatsnew/3.10.html),
  [3.11](https://docs.python.org/3/whatsnew/3.11.html),
  [3.12](https://docs.python.org/3/whatsnew/3.12.html),
  [3.13](https://docs.python.org/3/whatsnew/3.13.html),
  [3.14](https://docs.python.org/3/whatsnew/3.14.html).
- mypy strict-mode documentation:
  https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict.
