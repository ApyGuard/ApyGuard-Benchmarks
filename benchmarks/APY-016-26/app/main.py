from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-bulk-gap-secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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

_BULK_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the bulk export body.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "order_ids"],
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

_BULK_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _BULK_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Bulk Orders API",
    version="1.0.0",
    description=(
        "Bulk export benchmark: **bulk-export** returns rows for arbitrary order IDs without "
        "per-order ownership checks."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Orders", "description": "Single-order and bulk export."},
    ],
)
bearer = HTTPBearer()
USERS = {}
ORDERS = {}


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "bob@example.com", "password": "bob123"},
            ],
        },
    }


class BulkExportRequest(BaseModel):
    order_ids: list[int] = Field(description="List of numeric order IDs to include in the export.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"order_ids": [1001]}, {"order_ids": [1001, 2002]}],
        },
    }


def create_token(user: dict):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {"sub": str(user["id"]), "email": user["email"], "role": user["role"], "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event():
    global USERS, ORDERS
    with open("/flag.txt", encoding="utf-8") as handle:
        flag = handle.read().strip()

    USERS = {
        "alice@example.com": {"id": 1, "email": "alice@example.com", "role": "member", "password_hash": pwd_context.hash("alice123")},
        "bob@example.com": {"id": 2, "email": "bob@example.com", "role": "member", "password_hash": pwd_context.hash("bob123")},
    }

    ORDERS = {
        1001: {"id": 1001, "user_id": 1, "item": "notebook", "amount": 20},
        2002: {"id": 2002, "user_id": 2, "item": "server", "amount": 990, "internal_flag": flag},
    }


@app.get(
    "/ping",
    tags=["Health"],
    summary="Liveness probe",
    description="Returns a static JSON payload if the process is running.",
    operation_id="ping",
)
def ping():
    return {"ping": "pong"}


@app.post(
    "/api/auth/login",
    tags=["Authentication"],
    summary="Issue an access token",
    description="Authenticate with **email** and **password** and receive a JWT **access_token**.",
    operation_id="loginForAccessToken",
    responses=_LOGIN_OPENAPI_RESPONSES,
)
def login(
    payload: LoginRequest = Body(
        ...,
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token.",
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}},
            "bob": {"value": {"email": "bob@example.com", "password": "bob123"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/orders/{order_id}",
    tags=["Orders"],
    summary="Get order by ID",
    description="Returns a single order when it belongs to the caller (enforced).",
    operation_id="getOrderById",
)
def get_order(order_id: int, claims=Depends(current_claims)):
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="order not found")
    caller = USERS[claims["email"]]
    if order["user_id"] != caller["id"]:
        raise HTTPException(status_code=403, detail="forbidden")
    return order


@app.post(
    "/api/orders/bulk-export",
    tags=["Orders"],
    summary="Bulk export orders",
    description="Returns rows for all requested **order_ids** without per-id authorization (intentional gap).",
    operation_id="bulkExportOrders",
    responses=_BULK_OPENAPI_RESPONSES,
)
def bulk_export(
    payload: BulkExportRequest = Body(
        ...,
        description="JSON body listing **order_ids** to export.",
        openapi_examples={
            "own_order": {"value": {"order_ids": [1001]}},
            "mixed": {"value": {"order_ids": [1001, 2002]}},
        },
    ),
    _claims=Depends(current_claims),
):
    # Intentional vulnerability: no per-object ownership checks.
    return {"rows": [ORDERS[o] for o in payload.order_ids if o in ORDERS]}

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
