from pydantic import BaseModel, Field


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


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str

    model_config = {"from_attributes": True}


class OrderSummaryResponse(BaseModel):
    id: int
    item: str
    status: str
    total_cents: int
    is_priority: bool

    model_config = {"from_attributes": True}


class OrderDetailResponse(OrderSummaryResponse):
    internal_note: str
    user_id: int

    model_config = {"from_attributes": True}
