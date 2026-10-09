from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-coupon-secret"
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

_REDEEM_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error",
        "description": "Typical FastAPI HTTP 422 validation payload for the coupon redemption body.",
        "value": {
            "detail": [
                {
                    "type": "missing",
                    "loc": ["body", "code"],
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

_REDEEM_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation.",
        "content": {"application/json": {"examples": _REDEEM_VALIDATION_ERROR_JSON_EXAMPLES}},
    },
}

app = FastAPI(
    title="ApyGuard Coupon API",
    version="1.0.0",
    description=(
        "Coupon and wallet benchmark: a coupon code can be redeemed repeatedly to inflate credits "
        "and unlock VIP rewards."
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."},
        {"name": "Authentication", "description": "Obtain bearer tokens."},
        {"name": "Coupons", "description": "Coupon redemption."},
        {"name": "Wallet", "description": "Wallet balance and rewards."},
    ],
)
bearer_scheme = HTTPBearer()
USERS = {}
WALLETS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"},
        },
    }


class RedeemRequest(BaseModel):
    code: str = Field(description="Coupon code string.")

    model_config = {
        "json_schema_extra": {
            "examples": [{"code": "WELCOME10"}, {"code": "INVALID"}],
        },
    }


def create_token(email: str, user_id: int):
    exp = datetime.now(timezone.utc) + timedelta(minutes=60)
    return jwt.encode({"sub": str(user_id), "email": email, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def current_claims(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.on_event("startup")
def startup_event():
    global USERS, WALLETS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read().strip()
    USERS = {
        "alice@example.com": {"id": 1, "password_hash": pwd_context.hash("alice123")},
    }
    WALLETS = {"alice@example.com": {"credits": 0, "redeems": 0}}


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
        },
    ),
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["id"]), "token_type": "bearer"}


@app.post(
    "/api/coupons/redeem",
    tags=["Coupons"],
    summary="Redeem a coupon",
    description="Applies a coupon code to the authenticated user's wallet (business rules intentionally weak).",
    operation_id="redeemCoupon",
    responses=_REDEEM_OPENAPI_RESPONSES,
)
def redeem(
    payload: RedeemRequest = Body(
        ...,
        description="JSON body with **code** to redeem.",
        openapi_examples={
            "welcome": {"summary": "Valid benchmark code", "value": {"code": "WELCOME10"}},
        },
    ),
    claims=Depends(current_claims),
):
    email = claims["email"]
    wallet = WALLETS[email]

    # Intentional vulnerability: one coupon can be redeemed infinitely.
    if payload.code == "WELCOME10":
        wallet["credits"] += 10
        wallet["redeems"] += 1
        return {"status": "ok", "credits": wallet["credits"], "redeems": wallet["redeems"]}

    raise HTTPException(status_code=400, detail="Unknown coupon")


@app.get(
    "/api/wallet",
    tags=["Wallet"],
    summary="Wallet balance",
    description="Returns wallet credits; may include extra fields at high credit totals.",
    operation_id="getWallet",
)
def wallet(claims=Depends(current_claims)):
    email = claims["email"]
    wallet_data = dict(WALLETS[email])
    if wallet_data["credits"] >= 100:
        wallet_data["vip_reward"] = FLAG
    return wallet_data

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
