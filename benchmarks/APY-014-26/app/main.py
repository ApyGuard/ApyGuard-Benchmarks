from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-chain-secret"
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

_RESET_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the password reset body.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "token"],
                    "msg": "Field required",
                    "input": {"new_password": "NewAdmin!2026"},
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

_RESET_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _RESET_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Chained API",
    version="1.0.0",
    description=(
        "Chained-exploit benchmark combining order IDOR, reset-token reuse, and admin panel access."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Login and password reset."},
        {"name": "Orders", "description": "Order listing and detail."},
        {"name": "Admin", "description": "Administrative panel."},
    ],
)
bearer_scheme = HTTPBearer()
USERS = {}
ORDERS = {}
RESET_TOKENS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"},
                {"email": "admin@apy.local", "password": "InitialAdmin!"},
            ],
        },
    }


class ResetPasswordRequest(BaseModel):
    token: str = Field(description="Password reset token.")
    new_password: str = Field(description="New password to set.")

    model_config = {
        "json_schema_extra": {
            "example": {"token": "reset-admin-2-token", "new_password": "NewAdmin!2026"},
        },
    }


def create_token(user: dict):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {"sub": str(user["id"]), "email": user["email"], "role": user["role"], "exp": exp}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event():
    global USERS, ORDERS, RESET_TOKENS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()

    USERS = {
        "alice@example.com": {
            "id": 1,
            "email": "alice@example.com",
            "role": "member",
            "password_hash": pwd_context.hash("alice123"),
        },
        "admin@apy.local": {
            "id": 2,
            "email": "admin@apy.local",
            "role": "admin",
            "password_hash": pwd_context.hash("InitialAdmin!"),
            "admin_note": FLAG,
        },
    }

    RESET_TOKENS = {"reset-admin-2-token": "admin@apy.local"}

    ORDERS = {
        1: {"id": 1, "user_id": 1, "item": "starter-plan", "status": "paid"},
        2: {
            "id": 2,
            "user_id": 2,
            "item": "enterprise-plan",
            "status": "paid",
            "internal_note": "reset_token=reset-admin-2-token",
        },
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
            "admin": {"value": {"email": "admin@apy.local", "password": "InitialAdmin!"}},
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(user), "token_type": "bearer"}


@app.get(
    "/api/orders",
    tags=["Orders"],
    summary="List my orders",
    description="Returns orders owned by the authenticated user.",
    operation_id="listMyOrders",
)
def list_orders(claims=Depends(current_claims)):
    user = USERS[claims["email"]]
    return [order for order in ORDERS.values() if order["user_id"] == user["id"]]


@app.get(
    "/api/orders/{order_id}",
    tags=["Orders"],
    summary="Get order by ID",
    description="Returns order detail by **order_id** (ownership check intentionally missing).",
    operation_id="getOrderById",
)
def get_order(order_id: int, _claims=Depends(current_claims)):
    # Intentional vulnerability: missing ownership check (BOLA).
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="order not found")
    return order


@app.post(
    "/api/auth/reset-password",
    tags=["Authentication"],
    summary="Confirm password reset",
    description="Consumes a reset **token** and updates the account password.",
    operation_id="confirmPasswordReset",
    responses=_RESET_OPENAPI_RESPONSES,
)
def reset_password(
    payload: ResetPasswordRequest = Body(
        ...,
        description="JSON body with **token** and **new_password**.",
        openapi_examples={
            "from_order_leak": {
                "summary": "Token from order metadata",
                "value": {"token": "reset-admin-2-token", "new_password": "NewAdmin!2026"},
            },
        },
    ),
):
    email = RESET_TOKENS.get(payload.token)
    if not email or email not in USERS:
        raise HTTPException(status_code=400, detail="invalid token")
    USERS[email]["password_hash"] = pwd_context.hash(payload.new_password)
    return {"status": "password updated"}


@app.get(
    "/api/admin/panel",
    tags=["Admin"],
    summary="Admin panel",
    description="Admin-only panel when JWT **role** is **admin**.",
    operation_id="getAdminPanel",
)
def admin_panel(claims=Depends(current_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return {"admin": claims.get("email"), "flag": USERS[claims["email"]]["admin_note"]}

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
