from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ApyGuard Debug API"
    version="1.0.0"
    description=(
        "Benchmark for security misconfiguration: debug routes and permissive CORS expose "
        "sensitive runtime details without requiring authentication."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Debug", "description": "Debug and configuration exposure endpoints."}
    ]
)
FLAG = ""

# Intentional misconfiguration: broad CORS policy in production.
app.add_middleware(
    CORSMiddleware
    allow_origins=["*"]
    allow_credentials=True
    allow_methods=["*"]
    allow_headers=["*"]
)


@app.on_event("startup")
def startup_event:
    global FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip


@app.get(
    "/ping"
    tags=["Health"]
    summary="Liveness probe"
    description="Returns a static JSON payload if the process is running."
    operation_id="ping"
)
def ping:
    return {"ping": "pong"}


@app.get(
    "/api/debug/config"
    tags=["Debug"]
    summary="Debug configuration snapshot"
    description=(
        "Returns environment and internal configuration values intended for debugging. "
        "No authentication is required."
    )
    operation_id="getDebugConfig"
)
def debug_config:
    return {
        "environment": "production"
        "debug_mode": True
        "internal_signing_hint": "rotate-me-later"
        "flag": FLAG
    }

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
        tags=getattr(app, "openapi_tags", None)
    )
    _apyguard_promote_request_body_descriptions(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _apyguard_build_openapi
