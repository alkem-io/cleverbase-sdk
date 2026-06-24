#!/usr/bin/env python3
"""Render the Python binding's public surface to Markdown via pydoc-markdown.

The `cleverbase` runtime module is a compiled PyO3 extension: its `#[pyfunction]` definitions
carry no `__doc__`, and PEP 484 stubs are type-only by rule (ruff PYI021), so neither the compiled
module nor the stub holds docstrings. The durable documented contract is therefore the
mypy-strict-enforced *type signatures* in `bindings/python/cleverbase.pyi` (the four public
functions + `SCHEMA_VERSION`).

`pydoc-markdown`'s bundled Python loader resolves modules by import name and only finds `.py`
files (`docspec_python.find_module` ignores `.pyi`), so it cannot target the stub directly. This
script bridges that gap with the maintained library APIs: it parses the `.pyi` with
`docspec_python.parse_python_module` (the same parser the loader uses) and renders it with
pydoc-markdown's `MarkdownRenderer`. No SDK source is modified and nothing is copied/duplicated on
disk.

Usage: pyi_to_markdown.py <input.pyi> <output.md>
"""

from __future__ import annotations

import sys
from pathlib import Path

import docspec_python
from pydoc_markdown.contrib.renderers.markdown import MarkdownRenderer
from pydoc_markdown.interfaces import Context

# Module name shown as the page title; matches the importable extension module.
_MODULE_NAME = "cleverbase"

# CLI takes exactly: prog, <input.pyi>, <output.md>.
_EXPECTED_ARGC = 3


def render(pyi_path: Path) -> str:
    """Parse the `.pyi` stub and render its public surface to a Markdown string."""
    module = docspec_python.parse_python_module(pyi_path, module_name=_MODULE_NAME)
    renderer = MarkdownRenderer(
        # A self-contained API page: no table of contents, no HTML anchors, no source links.
        render_toc=False,
        insert_header_anchors=False,
        descriptive_class_title=False,
        add_method_class_prefix=False,
        source_linker=None,
        # Render functions as fenced code blocks carrying their full type signature.
        signature_code_block=True,
        # Show the type of module-level variables (e.g. `SCHEMA_VERSION: int`) in the header. We do
        # NOT enable `data_code_block`: the stub declares the type with no value, so a value block
        # would render a misleading `SCHEMA_VERSION = None`. The typed header is the real contract.
        data_code_block=False,
        render_typehint_in_data_header=True,
        code_headers=True,
        # The stub has no runtime .py source on disk to reformat; skip yapf (it needs a context dir
        # and would otherwise raise) — the signatures are already canonical.
        format_code=False,
    )
    # The renderer needs a Context (it reads `context.directory` to locate optional style files);
    # we render to a string and never write style files, so the cwd is a fine, side-effect-free dir.
    renderer.init(Context(directory="."))
    return renderer.render_to_string([module]).rstrip() + "\n"


def main(argv: list[str]) -> int:
    """CLI entry point: render <input.pyi> to <output.md>."""
    if len(argv) != _EXPECTED_ARGC:
        sys.stderr.write(f"usage: {argv[0]} <input.pyi> <output.md>\n")
        return 2
    pyi_path = Path(argv[1])
    out_path = Path(argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(pyi_path), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
