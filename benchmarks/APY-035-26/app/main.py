from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from lxml import etree
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-catalog-047"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer()

_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "email"],
                    "msg": "Field required",
                    "input": None,
                },
            ],
        },
    },
}

_IMPORT_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the catalog import body.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "document"],
                    "msg": "Field required",
                    "input": {},
                },
            ],
        },
    },
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

_IMPORT_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _IMPORT_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Catalog API",
    version="1.0.0",
    description="XML import benchmark with unsafe XXE-capable parsing.",
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Catalog", "description": "Catalog import and preview endpoints."},
    ],
)

USERS = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")


class ImportRequest(BaseModel):
    document: str = Field(description="XML catalog document to import.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"document": "<catalog><item><name>Widget</name><sku>W1</sku></item></catalog>"},
                {
                    "document": (
                        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY secret SYSTEM "
                        "'file:///flag.txt'>]><catalog><item><name>&secret;</name>"
                        "<sku>W1</sku></item></catalog>"
                    ),
                },
            ],
        },
    }


def create_token(email: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=45)
    return jwt.encode({"sub": email, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup() -> None:
    global USERS
    USERS = {
        "alice@example.com": {
            "password_hash": pwd_context.hash("alice123"),
            "role": "merchandiser",
        },
    }


@app.get("/ping", tags=["Health"], summary="Liveness probe", operation_id="ping")
def ping():
    return {"ping": "pong"}


@app.post(
    "/api/auth/login",
    tags=["Authentication"],
    summary="Issue an access token",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password**.",
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["role"]), "token_type": "bearer"}


@app.post(
    "/api/catalog/import",
    tags=["Catalog"],
    summary="Import a catalog XML document",
    description="Parses attacker-supplied XML import data.",
    operation_id="importCatalog",
    responses=_IMPORT_OPENAPI_RESPONSES,
)
def import_catalog(
    payload: ImportRequest = Body(
        ...,
        description="JSON body containing the XML **document** to import.",
        openapi_examples={
            "benign_catalog": {
                "summary": "Normal catalog import",
                "value": {
                    "document": "<catalog><item><name>Widget</name><sku>W1</sku></item></catalog>",
                },
            },
            "xxe_pattern": {
                "summary": "XXE-style import payload",
                "value": {
                    "document": (
                        "<?xml version='1.0'?><!DOCTYPE x [<!ENTITY secret SYSTEM "
                        "'file:///flag.txt'>]><catalog><item><name>&secret;</name>"
                        "<sku>W1</sku></item></catalog>"
                    ),
                },
            },
        },
    ),
    claims=Depends(current_claims),
):
    if claims.get("sub") not in USERS:
        raise HTTPException(status_code=401, detail="Unknown principal")

    # Intentional vulnerability: XXE-capable parser on untrusted XML.
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    try:
        root = etree.fromstring(payload.document.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"invalid xml: {exc}") from exc

    item = root.find(".//item")
    if item is None:
        raise HTTPException(status_code=400, detail="missing item element")

    name = item.findtext("name", default="")
    sku = item.findtext("sku", default="")
    return {
        "imported_by": claims.get("sub"),
        "item": {"name": name, "sku": sku},
        "status": "ok",
    }


def _apyguard_promote_request_body_descriptions(openapi_schema: dict) -> None:
    for _path, path_item in openapi_schema.get("paths", {}).items():
        for _method, op in path_item.items():
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody")
            if not rb or rb.get("description"):
                continue
            for _mt, med in rb.get("content", {}).items():
                sch = med.get("schema") or {}
                desc = sch.get("description")
                if desc:
                    rb["description"] = desc
                    break


def _apyguard_build_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        description=getattr(app, "description", None),
        routes=app.routes,
        tags=getattr(app, "openapi_tags", None),
    )
    _apyguard_promote_request_body_descriptions(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _apyguard_build_openapi
