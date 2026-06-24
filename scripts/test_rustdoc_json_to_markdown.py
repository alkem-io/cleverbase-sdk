#!/usr/bin/env python3
"""Unit tests for the rustdoc-JSON -> Markdown converter (scripts/rustdoc_json_to_markdown.py).

Run: .venv/bin/python -m pytest scripts/test_rustdoc_json_to_markdown.py

These exercise the type renderer across every shape the format-57 output of this workspace uses,
the per-kind emitters (struct/enum/fn/const/trait/type alias), re-export deduplication, and the
format-version guard — using small hand-built fixtures so the test is independent of any toolchain.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import rustdoc_json_to_markdown as r


def make_crate(index: dict[str, dict], root: str = "0", paths: dict | None = None) -> r.Crate:
    return r.Crate(
        {
            "format_version": r.SUPPORTED_FORMAT_VERSION,
            "root": int(root),
            "index": index,
            "paths": paths or {},
        }
    )


# --- type rendering ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ty,expected",
    [
        ({"primitive": "u32"}, "u32"),
        ({"generic": "T"}, "T"),
        ({"slice": {"primitive": "u8"}}, "[u8]"),
        ({"array": {"type": {"primitive": "u8"}, "len": "32"}}, "[u8; 32]"),
        ({"tuple": [{"primitive": "u8"}, {"primitive": "u16"}]}, "(u8, u16)"),
        ({"borrowed_ref": {"is_mutable": False, "type": {"primitive": "str"}}}, "&str"),
        (
            {"borrowed_ref": {"is_mutable": True, "lifetime": "'a", "type": {"primitive": "u8"}}},
            "&'a mut u8",
        ),
        ({"raw_pointer": {"is_mutable": True, "type": {"primitive": "u8"}}}, "*mut u8"),
        ({"raw_pointer": {"is_mutable": False, "type": {"primitive": "u8"}}}, "*const u8"),
        (None, "_"),
    ],
)
def test_render_type_shapes(ty, expected):
    assert r.render_type(make_crate({}), ty) == expected


def test_render_resolved_path_with_generics():
    crate = make_crate({})
    ty = {
        "resolved_path": {
            "path": "core::result::Result",
            "args": {
                "angle_bracketed": {
                    "args": [
                        {"type": {"primitive": "u8"}},
                        {"type": {"resolved_path": {"path": "crate::Error", "args": None}}},
                    ],
                    "constraints": [],
                }
            },
        }
    }
    assert r.render_type(crate, ty) == "Result<u8, Error>"


def test_render_unsupported_type_is_marked_not_swallowed():
    out = r.render_type(make_crate({}), {"some_future_shape": 1})
    assert "unsupported type" in out


# --- signature rendering -------------------------------------------------------------------------


def test_function_signature_with_self_and_generics():
    crate = make_crate({})
    func = {
        "header": {"is_const": False, "is_async": False, "is_unsafe": False, "abi": "Rust"},
        "generics": {
            "params": [{"name": "T", "kind": {"type": {"bounds": []}}}],
            "where_predicates": [],
        },
        "sig": {
            "inputs": [
                ["self", {"borrowed_ref": {"is_mutable": False, "type": {"generic": "Self"}}}],
                ["value", {"primitive": "u8"}],
            ],
            "output": {"primitive": "bool"},
            "is_c_variadic": False,
        },
    }
    assert (
        r.render_function_signature(crate, "check", func) == "fn check<T>(&self, value: u8) -> bool"
    )


def test_function_signature_extern_c_unsafe():
    crate = make_crate({})
    func = {
        "header": {"is_const": False, "is_async": False, "is_unsafe": True, "abi": {"C": None}},
        "generics": {"params": [], "where_predicates": []},
        "sig": {
            "inputs": [["p", {"raw_pointer": {"is_mutable": True, "type": {"primitive": "u8"}}}]],
            "output": {"primitive": "i32"},
            "is_c_variadic": False,
        },
    }
    assert (
        r.render_function_signature(crate, "f", func) == 'unsafe extern "C" fn f(p: *mut u8) -> i32'
    )


# --- full-document emission ----------------------------------------------------------------------


def _doc_module(items):
    return {
        "id": 0,
        "name": "mycrate",
        "docs": "Crate overview.",
        "inner": {"module": {"is_crate": True, "items": items, "is_stripped": False}},
    }


def test_struct_with_fields_and_method():
    index = {
        "0": _doc_module([10, 30]),
        # struct Foo { a: u8 }
        "10": {
            "id": 10,
            "name": "Foo",
            "docs": "A struct.",
            "inner": {
                "struct": {
                    "kind": {"plain": {"fields": [11], "has_stripped_fields": False}},
                    "generics": {"params": [], "where_predicates": []},
                    "impls": [20],
                }
            },
        },
        "11": {
            "id": 11,
            "name": "a",
            "docs": "field a",
            "inner": {"struct_field": {"primitive": "u8"}},
        },
        # inherent impl with one method
        "20": {
            "id": 20,
            "name": None,
            "docs": None,
            "inner": {
                "impl": {
                    "trait": None,
                    "is_synthetic": False,
                    "blanket_impl": None,
                    "generics": {"params": [], "where_predicates": []},
                    "items": [21],
                }
            },
        },
        "21": {
            "id": 21,
            "name": "make",
            "docs": "Build one.",
            "inner": {
                "function": {
                    "header": {
                        "is_const": False,
                        "is_async": False,
                        "is_unsafe": False,
                        "abi": "Rust",
                    },
                    "generics": {"params": [], "where_predicates": []},
                    "sig": {
                        "inputs": [],
                        "output": {"resolved_path": {"path": "Foo", "args": None}},
                        "is_c_variadic": False,
                    },
                }
            },
        },
        # a trait impl that must be ignored
        "30": {
            "id": 30,
            "name": None,
            "docs": None,
            "inner": {
                "impl": {
                    "trait": {"path": "Clone", "args": None},
                    "is_synthetic": False,
                    "blanket_impl": None,
                    "generics": {"params": [], "where_predicates": []},
                    "items": [],
                }
            },
        },
    }
    md = r.crate_to_markdown(
        {"format_version": r.SUPPORTED_FORMAT_VERSION, "root": 0, "index": index, "paths": {}}
    )
    assert "# Crate `mycrate`" in md
    assert "Crate overview." in md
    assert "struct `Foo`" in md
    assert "`a: u8`" in md
    assert "field a" in md
    assert "fn make() -> Foo" in md
    assert "Build one." in md


def test_enum_variants_rendered():
    index = {
        "0": _doc_module([10]),
        "10": {
            "id": 10,
            "name": "Color",
            "docs": "colors",
            "inner": {
                "enum": {
                    "generics": {"params": [], "where_predicates": []},
                    "variants": [11, 12],
                    "impls": [],
                }
            },
        },
        "11": {
            "id": 11,
            "name": "Red",
            "docs": "the red one",
            "inner": {"variant": {"kind": "plain", "discriminant": None}},
        },
        "12": {
            "id": 12,
            "name": "Rgb",
            "docs": None,
            "inner": {"variant": {"kind": {"tuple": [13]}, "discriminant": None}},
        },
        "13": {"id": 13, "name": "0", "docs": None, "inner": {"struct_field": {"primitive": "u8"}}},
    }
    md = r.crate_to_markdown(
        {"format_version": r.SUPPORTED_FORMAT_VERSION, "root": 0, "index": index, "paths": {}}
    )
    assert "enum `Color`" in md
    assert "`Red`" in md
    assert "the red one" in md
    assert "`Rgb(u8)`" in md


def test_constant_rendered():
    index = {
        "0": _doc_module([10]),
        "10": {
            "id": 10,
            "name": "VERSION",
            "docs": "the version",
            "inner": {
                "constant": {
                    "type": {"primitive": "u32"},
                    "const": {"expr": "1", "value": "1u32", "is_literal": True},
                }
            },
        },
    }
    md = r.crate_to_markdown(
        {"format_version": r.SUPPORTED_FORMAT_VERSION, "root": 0, "index": index, "paths": {}}
    )
    assert "const `VERSION`" in md
    assert "const VERSION: u32 = 1" in md


def test_reexport_of_module_owned_item_is_not_duplicated():
    # Root re-exports `Inner` which is owned by submodule `sub` — it must render once (in `sub`).
    index = {
        "0": {
            "id": 0,
            "name": "mycrate",
            "docs": None,
            "inner": {"module": {"is_crate": True, "items": [1, 40], "is_stripped": False}},
        },
        # submodule sub { struct Inner }
        "1": {
            "id": 1,
            "name": "sub",
            "docs": "a submodule",
            "inner": {"module": {"is_crate": False, "items": [2], "is_stripped": False}},
        },
        "2": {
            "id": 2,
            "name": "Inner",
            "docs": "the inner struct",
            "inner": {
                "struct": {
                    "kind": {"unit": None},
                    "generics": {"params": [], "where_predicates": []},
                    "impls": [],
                }
            },
        },
        # pub use sub::Inner at the root
        "40": {
            "id": 40,
            "name": "Inner",
            "docs": None,
            "inner": {"use": {"source": "sub::Inner", "name": "Inner", "id": 2, "is_glob": False}},
        },
    }
    md = r.crate_to_markdown(
        {"format_version": r.SUPPORTED_FORMAT_VERSION, "root": 0, "index": index, "paths": {}}
    )
    assert md.count("struct `Inner`") == 1


def test_format_version_guard():
    with pytest.raises(SystemExit):
        r.crate_to_markdown({"format_version": 1, "root": 0, "index": {}, "paths": {}})


def test_real_crate_fixture_if_present():
    # When the rustdoc JSON has been generated, smoke-test the real public surface end to end.
    json_path = Path(__file__).resolve().parent.parent / "target" / "doc" / "cleverbase_core.json"
    if not json_path.exists():
        pytest.skip("rustdoc JSON not generated; run scripts/gen-docs.sh first")
    md = r.crate_to_markdown(json.loads(json_path.read_text(encoding="utf-8")))
    for symbol in (
        "fn `begin`",
        "fn `resume`",
        "struct `SigningRequest`",
        "enum `ConformanceLevel`",
        "enum `Step`",
        "const `SCHEMA_VERSION`",
    ):
        assert symbol in md, f"missing {symbol}"
    assert "unsupported type" not in md
