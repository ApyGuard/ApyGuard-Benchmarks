from datetime import datetime, timedelta, timezone

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

SECRET_KEY = "apyguard-rules-042"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer

_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "email"]
                    "msg": "Field required"
                    "input": None
                }
            ]
        }
    }
}

_PREVIEW_VALIDATION_ERROR_JSON_EXAMPLES = {
    "validation_error": {
        "summary": "Validation error"
        "description": "Typical FastAPI HTTP 422 validation payload for the preview body."
        "value": {
            "detail": [
                {
                    "type": "missing"
                    "loc": ["body", "expression"]
                    "msg": "Field required"
                    "input": {}
                }
            ]
        }
    }
}

_LOGIN_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

_PREVIEW_OPENAPI_RESPONSES = {
    422: {
        "description": "Request body failed validation."
        "content": {"application/json": {"examples": _PREVIEW_VALIDATION_ERROR_JSON_EXAMPLES}}
    }
}

app = FastAPI(
    title="ApyGuard Rules API"
    version="1.0.0"
    description=(
        "Rule preview benchmark: **expression** is evaluated with Python **eval** under a weak filter."
    )
    openapi_tags=[
        {"name": "Health", "description": "Liveness and connectivity checks."}
        {"name": "Authentication", "description": "Obtain bearer tokens."}
        {"name": "Rules", "description": "Expression preview."}
    ]
)

USERS = {}
FLAG = ""


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "example": {"email": "alice@example.com", "password": "alice123"}
        }
    }


class RulePreviewRequest(BaseModel):
    expression: str = Field(description="Python expression to evaluate (dangerous).")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"expression": "1 + 1"}
                {"expression": "flag"}
            ]
        }
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
def startup -> None:
    global USERS, FLAG
    with open("/flag.txt", encoding="utf-8") as handle:
        FLAG = handle.read.strip

    USERS = {
        "alice@example.com": {"password_hash": pwd_context.hash("alice123"), "role": "member"}
    }


@app.get(
    "/ping"
    tags=["Health"]
    summary="Liveness probe"
    description="Returns a static JSON payload if the process is running."
    operation_id="ping"
)
def ping:
    return {"ping": "pong"}


@app.post(
    "/api/auth/login"
    tags=["Authentication"]
    summary="Issue an access token"
    operation_id="loginForAccessToken"
    responses=_LOGIN_OPENAPI_RESPONSES
)
def login(
    payload: LoginRequest = Body(
        ...
        description="JSON request body (**application/json**) with **email** and **password** for obtaining a bearer access token."
        openapi_examples={
            "alice": {"value": {"email": "alice@example.com", "password": "alice123"}}
        }
    )
):
    user = USERS.get(payload.email)
    if not user or not pwd_context.verify(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return {"access_token": create_token(payload.email, user["role"]), "token_type": "bearer"}


@app.post(
    "/api/rules/preview"
    tags=["Rules"]
    summary="Preview rule expression"
    description="Evaluates **expression** with **flag** in scope (unsafe)."
    operation_id="previewRuleExpression"
    responses=_PREVIEW_OPENAPI_RESPONSES
)
def preview_rule(
    payload: RulePreviewRequest = Body(
        ...
        description="JSON body with **expression** string."
        openapi_examples={
            "add": {"value": {"expression": "1 + 2"}}
        }
    )
    claims=Depends(current_claims)
):
    if claims.get("sub") not in USERS:
        raise HTTPException(status_code=401, detail="Unknown principal")

    expr = payload.expression.strip
    if len(expr) > 180:
        raise HTTPException(status_code=400, detail="Expression too long")

    # Intentional vulnerability:
    # weak filters with direct eval still permit dangerous expression execution.
    if ";" in expr:
        raise HTTPException(status_code=400, detail="Semicolons not allowed")

    try:
        result = eval(expr, {"__builtins__": __builtins__}, {"flag": FLAG})  # noqa: S307
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Evaluation error: {exc}") from exc

    return {"status": "ok", "expression": expr, "result": str(result)}

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
