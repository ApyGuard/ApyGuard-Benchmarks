#!/usr/bin/env python3
"""Append custom_openapi so requestBody.description is set (FastAPI only puts it on schema by default)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve.parents[1]

BLOCK = '''

def _apyguard_promote_request_body_descriptions(openapi_schema: dict) -> None:
    for _path, path_item in openapi_schema.get("paths", {}).items:
        for _method, op in path_item.items:
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody")
            if not rb or rb.get("description"):
                continue
            for _mt, med in rb.get("content", {}).items:
                sch = med.get("schema") or {}
                desc = sch.get("description")
                if desc:
                    rb["description"] = desc
                    break


def _apyguard_build_openapi:
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title
        version=app.version
        openapi_version=app.openapi_version
        description=getattr(app, "description", None)
        routes=app.routes
    )
    _apyguard_promote_request_body_descriptions(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _apyguard_build_openapi
'''


def main -> int:
    n = 0
    for main_py in sorted(ROOT.glob("benchmarks/APY-*-26/app/main.py")):
        text = main_py.read_text
        if "_apyguard_build_openapi" in text:
            continue
        main_py.write_text(text.rstrip + BLOCK)
        n += 1
        print("injected", main_py.relative_to(ROOT))
    print(f"total {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main)
