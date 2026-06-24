#!/usr/bin/env python3
"""Convert rustdoc JSON into browseable Markdown for the SDK's public Rust API.

rustdoc is HTML-native, so to commit browseable Markdown we instead consume rustdoc's machine
output: `cargo rustdoc -- -Z unstable-options --output-format json` (enabled on the pinned stable
1.92.0 via `RUSTC_BOOTSTRAP=1`). The off-the-shelf converters on crates.io/npm lag the rustdoc JSON
`format_version` (e.g. rustdoc-md targets v42 while 1.92 emits v57), so a stale converter would
silently drop or mis-render items. This script instead walks the JSON we control directly and is
unit-tested (`scripts/test_rustdoc_json_to_markdown.py`), pinning the format version it supports.

It emits one Markdown file per crate: the crate-level overview (the `//!` module docs), then the
public items grouped by kind — modules, structs (with fields + inherent methods), enums (with
variants + inherent methods), traits, functions, constants, type aliases, macros — each with its
doc comment and a Rust-rendered signature. Re-exports (`pub use`) are followed so the rendered
surface matches what `pub use` exposes at the crate root.

Usage: rustdoc_json_to_markdown.py <crate.json> <output.md>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# The rustdoc JSON schema is unstable and versioned. We have verified the walking logic against
# this version (Rust 1.92.0, pinned by rust-toolchain.toml). A toolchain bump that changes the
# format is a deliberate event: fail loudly rather than emit silently-wrong docs.
SUPPORTED_FORMAT_VERSION = 57

# CLI takes exactly: prog, <crate.json>, <output.md>.
_EXPECTED_ARGC = 3


class Crate:
    """A loaded rustdoc JSON document with convenience lookups over its `index`/`paths`."""

    def __init__(self, data: dict[str, Any]) -> None:
        """Index the rustdoc document and precompute the module-owned id set for dedup."""
        self.data = data
        self.index: dict[str, Any] = data["index"]
        self.paths: dict[str, Any] = data["paths"]
        self.root: str = str(data["root"])
        # Ids of items that have a canonical home directly inside some module (i.e. they are listed
        # as a non-`use` member of a `module`). A `pub use` re-export of such an item — common at
        # the crate root, e.g. `pub use types::ConformanceLevel` — must NOT be expanded again, or
        # the item would render twice. We expand a re-export only when its target has no module home
        # of its own in this crate.
        self.module_owned: set[str] = set()
        for item in self.index.values():
            inner = item.get("inner", {})
            module = inner.get("module")
            if module is None:
                continue
            for member_id in module.get("items", []):
                member = self.index.get(str(member_id))
                if member is not None and "use" not in member.get("inner", {}):
                    self.module_owned.add(str(member_id))

    def item(self, item_id: Any) -> dict[str, Any] | None:
        """Return the index entry for an id, or None if it was stripped (private / external)."""
        return self.index.get(str(item_id))

    def name_for(self, item_id: Any) -> str | None:
        """Best-effort short name for an id, from the index or the paths table."""
        item = self.item(item_id)
        if item and item.get("name"):
            return item["name"]
        path = self.paths.get(str(item_id))
        if path and path.get("path"):
            return path["path"][-1]
        return None


# --------------------------------------------------------------------------------------------------
# Type rendering — turn a rustdoc `Type`/`GenericArgs` node back into readable Rust source.
# Covers every shape observed in the format-57 output of this workspace; unknown shapes degrade to a
# clearly-marked placeholder rather than crashing, so a future shape is visible, never silent.
# --------------------------------------------------------------------------------------------------


def render_type(crate: Crate, ty: Any) -> str:
    """Render a rustdoc `Type` node as Rust source (e.g. `&[u8]`, `Result<T, Error>`)."""
    if ty is None:
        return "_"
    if not isinstance(ty, dict):
        # Bare strings appear for some primitives in older shapes; pass through.
        return str(ty)

    if "primitive" in ty:
        return ty["primitive"]
    if "generic" in ty:
        return ty["generic"]
    if "resolved_path" in ty:
        return _render_path(crate, ty["resolved_path"])
    if "borrowed_ref" in ty:
        ref = ty["borrowed_ref"]
        lifetime = f"{ref['lifetime']} " if ref.get("lifetime") else ""
        mut = "mut " if ref.get("is_mutable") else ""
        return f"&{lifetime}{mut}{render_type(crate, ref['type'])}"
    if "raw_pointer" in ty:
        ptr = ty["raw_pointer"]
        mut = "mut " if ptr.get("is_mutable") else "const "
        return f"*{mut}{render_type(crate, ptr['type'])}"
    if "slice" in ty:
        return f"[{render_type(crate, ty['slice'])}]"
    if "array" in ty:
        arr = ty["array"]
        return f"[{render_type(crate, arr['type'])}; {arr['len']}]"
    if "tuple" in ty:
        return "(" + ", ".join(render_type(crate, t) for t in ty["tuple"]) + ")"
    if "qualified_path" in ty:
        qp = ty["qualified_path"]
        self_ty = render_type(crate, qp["self_type"])
        return f"<{self_ty}>::{qp['name']}"
    if "impl_trait" in ty:
        return "impl " + " + ".join(_render_generic_bound(crate, b) for b in ty["impl_trait"])
    if "dyn_trait" in ty:
        dt = ty["dyn_trait"]
        traits = " + ".join(_render_path(crate, t["trait"]) for t in dt.get("traits", []))
        lifetime = dt.get("lifetime")
        if lifetime:
            traits = f"{traits} + {lifetime}" if traits else lifetime
        return f"dyn {traits}"
    # Unknown shape: surface it instead of swallowing it.
    return f"/* unsupported type: {sorted(ty)} */"


def _render_path(crate: Crate, path: dict[str, Any]) -> str:
    """Render a `resolved_path`: the last path segment plus any generic arguments."""
    name = path["path"].split("::")[-1]
    args = path.get("args")
    return name + _render_generic_args(crate, args)


def _render_generic_args(crate: Crate, args: Any) -> str:
    """Render `<...>` generic arguments (angle-bracketed) or `(...)`-style fn arg lists."""
    if not args:
        return ""
    if "angle_bracketed" in args:
        ab = args["angle_bracketed"]
        parts: list[str] = []
        for arg in ab.get("args", []):
            if "type" in arg:
                parts.append(render_type(crate, arg["type"]))
            elif "lifetime" in arg:
                parts.append(arg["lifetime"])
            elif "const" in arg:
                parts.append(arg["const"].get("expr", "_"))
        parts.extend(_render_constraint(crate, c) for c in ab.get("constraints", []))
        return "<" + ", ".join(parts) + ">" if parts else ""
    if "parenthesized" in args:
        pz = args["parenthesized"]
        inputs = ", ".join(render_type(crate, t) for t in pz.get("inputs", []))
        out = pz.get("output")
        ret = f" -> {render_type(crate, out)}" if out else ""
        return f"({inputs}){ret}"
    return ""


def _render_constraint(crate: Crate, constraint: dict[str, Any]) -> str:
    """Render an associated-type constraint, e.g. `Item = u8`."""
    name = constraint.get("name", "")
    binding = constraint.get("binding", {})
    if "equality" in binding:
        eq = binding["equality"]
        if "type" in eq:
            return f"{name} = {render_type(crate, eq['type'])}"
    return name


def _render_generic_bound(crate: Crate, bound: dict[str, Any]) -> str:
    """Render a single generic bound (trait bound or lifetime)."""
    if "trait_bound" in bound:
        tb = bound["trait_bound"]
        modifier = tb.get("modifier")
        prefix = "?" if modifier == "maybe" else ""
        return prefix + _render_path(crate, tb["trait"])
    if "outlives" in bound:
        return bound["outlives"]
    return ""


# --------------------------------------------------------------------------------------------------
# Signature rendering for the documented item kinds.
# --------------------------------------------------------------------------------------------------


def _render_generics_params(crate: Crate, generics: Any) -> str:
    """Render the `<T: Bound, 'a>` parameter list of a generic item (empty when there are none)."""
    if not generics:
        return ""
    params = generics.get("params", [])
    rendered: list[str] = []
    for param in params:
        kind = param.get("kind", {})
        if "lifetime" in kind:
            rendered.append(param["name"])
        elif "type" in kind:
            bounds = kind["type"].get("bounds", [])
            bound_str = ""
            if bounds:
                bound_str = ": " + " + ".join(_render_generic_bound(crate, b) for b in bounds)
            rendered.append(param["name"] + bound_str)
        elif "const" in kind:
            rendered.append(f"const {param['name']}: {render_type(crate, kind['const']['type'])}")
    return "<" + ", ".join(rendered) + ">" if rendered else ""


def render_function_signature(crate: Crate, name: str, func: dict[str, Any]) -> str:
    """Render a `fn`/method signature including qualifiers, generics, args and return type."""
    header = func.get("header", {})
    qualifiers = ""
    if header.get("is_const"):
        qualifiers += "const "
    if header.get("is_async"):
        qualifiers += "async "
    if header.get("is_unsafe"):
        qualifiers += "unsafe "
    abi = header.get("abi")
    if (isinstance(abi, dict) and "C" in abi) or abi == "C":
        qualifiers += 'extern "C" '

    generics = _render_generics_params(crate, func.get("generics"))
    sig = func["sig"]
    inputs = []
    for arg_name, arg_ty in sig.get("inputs", []):
        if arg_name == "self":
            # Render the receiver compactly: `&self`, `&mut self`, `self`.
            inputs.append(_render_self(arg_ty))
        else:
            inputs.append(f"{arg_name}: {render_type(crate, arg_ty)}")
    if sig.get("is_c_variadic"):
        inputs.append("...")
    output = sig.get("output")
    ret = f" -> {render_type(crate, output)}" if output else ""
    return f"{qualifiers}fn {name}{generics}({', '.join(inputs)}){ret}"


def _render_self(ty: Any) -> str:
    """Render a method receiver argument as `self` / `&self` / `&mut self`."""
    if isinstance(ty, dict) and "borrowed_ref" in ty:
        ref = ty["borrowed_ref"]
        inner = ref["type"]
        if isinstance(inner, dict) and inner.get("generic") == "Self":
            return "&mut self" if ref.get("is_mutable") else "&self"
    return "self"


# --------------------------------------------------------------------------------------------------
# Markdown emission.
# --------------------------------------------------------------------------------------------------


class MarkdownBuilder:
    """Accumulates Markdown lines for one crate."""

    def __init__(self, crate: Crate) -> None:
        """Start an empty buffer bound to the crate being rendered."""
        self.crate = crate
        self.lines: list[str] = []

    def add_docs(self, item: dict[str, Any]) -> None:
        """Append an item's doc comment (already Markdown in rustdoc) as a block."""
        docs = item.get("docs")
        if docs:
            self.lines.append(docs.rstrip())
            self.lines.append("")

    def heading(self, level: int, text: str) -> None:
        """Append a Markdown heading at the given level."""
        self.lines.append(f"{'#' * level} {text}")
        self.lines.append("")

    def code(self, text: str) -> None:
        """Append a fenced ```rust code block."""
        self.lines.append("```rust")
        self.lines.append(text)
        self.lines.append("```")
        self.lines.append("")

    def text(self, line: str = "") -> None:
        """Append a raw Markdown line (default: a blank line)."""
        self.lines.append(line)

    def render(self) -> str:
        """Join the buffered lines, collapsing runs of blank lines to one."""
        out: list[str] = []
        blanks = 0
        for line in self.lines:
            if line.strip() == "":
                blanks += 1
                if blanks > 1:
                    continue
            else:
                blanks = 0
            out.append(line.rstrip())
        return "\n".join(out).strip("\n") + "\n"


def _collect_module_items(crate: Crate, module_item: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve a module's `items`, following `pub use` re-exports to the items they expose."""
    resolved: list[dict[str, Any]] = []
    seen: set[str] = set()
    for child_id in module_item["inner"]["module"]["items"]:
        child = crate.item(child_id)
        if child is None:
            continue
        inner = child.get("inner", {})
        if "use" in inner:
            # Follow a re-export only when its target has no canonical module home in this crate
            # (otherwise it renders at that home, and expanding here would duplicate it).
            target = crate.item(inner["use"]["id"])
            if (
                target is not None
                and str(target["id"]) not in crate.module_owned
                and str(target["id"]) not in seen
            ):
                seen.add(str(target["id"]))
                resolved.append(target)
            continue
        if str(child["id"]) not in seen:
            seen.add(str(child["id"]))
            resolved.append(child)
    return resolved


def _kind_of(item: dict[str, Any]) -> str:
    """The single inner-kind key for an item (e.g. 'struct', 'enum', 'function')."""
    inner = item.get("inner", {})
    return next(iter(inner), "unknown")


def _inherent_methods(crate: Crate, item: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the public inherent (non-trait, non-auto, non-blanket) methods of a struct/enum."""
    inner = item.get("inner", {})
    type_inner = inner.get(_kind_of(item), {})
    methods: list[dict[str, Any]] = []
    for impl_id in type_inner.get("impls", []):
        impl_item = crate.item(impl_id)
        if impl_item is None:
            continue
        impl = impl_item["inner"]["impl"]
        # Skip trait impls, auto/synthetic impls, and blanket impls — we document the inherent API.
        if impl.get("trait") is not None or impl.get("is_synthetic") or impl.get("blanket_impl"):
            continue
        for method_id in impl.get("items", []):
            method = crate.item(method_id)
            if method is not None and "function" in method.get("inner", {}):
                methods.append(method)
    methods.sort(key=lambda m: m.get("name") or "")
    return methods


def _emit_struct(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"struct `{item['name']}`")
    generics = _render_generics_params(crate, item["inner"]["struct"].get("generics"))
    md.code(f"struct {item['name']}{generics}")
    md.add_docs(item)
    kind = item["inner"]["struct"]["kind"]
    fields: list[Any] = []
    if isinstance(kind, dict) and "plain" in kind:
        fields = kind["plain"].get("fields", [])
    elif isinstance(kind, dict) and "tuple" in kind:
        fields = [f for f in kind["tuple"] if f is not None]
    field_items = [crate.item(f) for f in fields]
    field_items = [f for f in field_items if f is not None]
    if field_items:
        md.heading(level + 1, "Fields")
        for fld in field_items:
            ty = render_type(crate, fld["inner"]["struct_field"])
            md.text(f"- `{fld['name']}: {ty}`")
            if fld.get("docs"):
                md.text(f"  - {fld['docs'].strip()}")
        md.text("")
    _emit_methods(crate, md, item, level)


def _emit_enum(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"enum `{item['name']}`")
    generics = _render_generics_params(crate, item["inner"]["enum"].get("generics"))
    md.code(f"enum {item['name']}{generics}")
    md.add_docs(item)
    variants = item["inner"]["enum"].get("variants", [])
    variant_items = [crate.item(v) for v in variants]
    variant_items = [v for v in variant_items if v is not None]
    if variant_items:
        md.heading(level + 1, "Variants")
        for var in variant_items:
            md.text(f"- `{_render_variant(crate, var)}`")
            if var.get("docs"):
                md.text(f"  - {var['docs'].strip()}")
        md.text("")
    _emit_methods(crate, md, item, level)


def _render_variant(crate: Crate, var: dict[str, Any]) -> str:
    """Render an enum variant: plain, tuple `(T, U)`, or struct `{ a: T }`."""
    name = var["name"]
    kind = var["inner"]["variant"]["kind"]
    if isinstance(kind, str):  # "plain"
        return name
    if "tuple" in kind:
        tys = []
        for fid in kind["tuple"]:
            if fid is None:
                continue
            fld = crate.item(fid)
            if fld is not None:
                tys.append(render_type(crate, fld["inner"]["struct_field"]))
        return f"{name}({', '.join(tys)})"
    if "struct" in kind:
        parts = []
        for fid in kind["struct"].get("fields", []):
            fld = crate.item(fid)
            if fld is not None:
                parts.append(f"{fld['name']}: {render_type(crate, fld['inner']['struct_field'])}")
        return f"{name} {{ {', '.join(parts)} }}"
    return name


def _emit_methods(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    methods = _inherent_methods(crate, item)
    if not methods:
        return
    md.heading(level + 1, "Methods")
    for method in methods:
        md.code(render_function_signature(crate, method["name"], method["inner"]["function"]))
        md.add_docs(method)


def _emit_trait(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"trait `{item['name']}`")
    generics = _render_generics_params(crate, item["inner"]["trait"].get("generics"))
    md.code(f"trait {item['name']}{generics}")
    md.add_docs(item)
    for method_id in item["inner"]["trait"].get("items", []):
        method = crate.item(method_id)
        if method is None:
            continue
        inner = method.get("inner", {})
        if "function" in inner:
            md.code(render_function_signature(crate, method["name"], inner["function"]))
            md.add_docs(method)


def _emit_function(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"fn `{item['name']}`")
    md.code(render_function_signature(crate, item["name"], item["inner"]["function"]))
    md.add_docs(item)


def _emit_constant(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"const `{item['name']}`")
    const = item["inner"]["constant"]
    ty = render_type(crate, const["type"])
    expr = const.get("const", {}).get("expr", "")
    value = f" = {expr}" if expr else ""
    md.code(f"const {item['name']}: {ty}{value}")
    md.add_docs(item)


def _emit_type_alias(crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    md.heading(level, f"type `{item['name']}`")
    alias = item["inner"]["type_alias"]
    generics = _render_generics_params(crate, alias.get("generics"))
    md.code(f"type {item['name']}{generics} = {render_type(crate, alias['type'])}")
    md.add_docs(item)


def _emit_macro(_crate: Crate, md: MarkdownBuilder, item: dict[str, Any], level: int) -> None:
    # `_crate` is unused but kept for the uniform emitter signature used by `_SECTIONS`.
    md.heading(level, f"macro `{item['name']}!`")
    md.add_docs(item)


# Item kinds we render, in a stable display order, each with its emitter and section heading.
_SECTIONS: list[tuple[str, str, Any]] = [
    ("module", "Modules", None),  # modules recurse; handled specially
    ("struct", "Structs", _emit_struct),
    ("enum", "Enums", _emit_enum),
    ("trait", "Traits", _emit_trait),
    ("function", "Functions", _emit_function),
    ("constant", "Constants", _emit_constant),
    ("type_alias", "Type aliases", _emit_type_alias),
    ("macro", "Macros", _emit_macro),
]


def _emit_module(
    crate: Crate, md: MarkdownBuilder, module_item: dict[str, Any], level: int
) -> None:
    """Emit a module and recurse into submodules, grouping items by kind."""
    items = _collect_module_items(crate, module_item)
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for it in items:
        by_kind.setdefault(_kind_of(it), []).append(it)

    for kind, section_title, emitter in _SECTIONS:
        members = sorted(by_kind.get(kind, []), key=lambda m: m.get("name") or "")
        if not members:
            continue
        if kind == "module":
            for sub in members:
                md.heading(level, f"Module `{sub['name']}`")
                md.add_docs(sub)
                _emit_module(crate, md, sub, level + 1)
            continue
        md.heading(level, section_title)
        for member in members:
            emitter(crate, md, member, level + 1)


def crate_to_markdown(data: dict[str, Any]) -> str:
    """Render a full rustdoc-JSON document to a single Markdown string."""
    fmt = data.get("format_version")
    if fmt != SUPPORTED_FORMAT_VERSION:
        raise SystemExit(
            f"rustdoc JSON format_version {fmt} != supported {SUPPORTED_FORMAT_VERSION}; "
            "the rustdoc schema changed — update scripts/rustdoc_json_to_markdown.py "
            "(and its tests) for the new toolchain."
        )
    crate = Crate(data)
    root = crate.item(crate.root)
    if root is None:
        msg = "rustdoc JSON has no root module"
        raise SystemExit(msg)

    md = MarkdownBuilder(crate)
    md.heading(1, f"Crate `{root['name']}`")
    md.add_docs(root)  # the crate-level `//!` overview
    _emit_module(crate, md, root, 2)
    return md.render()


def main(argv: list[str]) -> int:
    """CLI entry point: convert <crate.json> to <output.md>."""
    if len(argv) != _EXPECTED_ARGC:
        sys.stderr.write(f"usage: {argv[0]} <crate.json> <output.md>\n")
        return 2
    data = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    out_path = Path(argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(crate_to_markdown(data), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
