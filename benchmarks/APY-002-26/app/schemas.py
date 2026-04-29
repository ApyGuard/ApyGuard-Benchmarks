from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str = Field(description="Account email address.")
    password: str = Field(description="Account password.")

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "alice@example.com", "password": "alice123"}
                {"email": "admin@apy.local", "password": "UltraSecretAdmin!"}
            ]
        }
    }


class TokenResponse(BaseModel):
    access_token: str = Field(description="JWT bearer access token.")
    token_type: str = Field(description="Token type; always `bearer` for this API.")


class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    full_name: str

    model_config = {"from_attributes": True}


class TicketResponse(BaseModel):
    id: int
    subject: str
    status: str
    owner_email: str
    public_note: str

    model_config = {"from_attributes": True}


class AdminExportRequest(BaseModel):
    async_delivery: bool = Field(
        default=False
        description="If true, export would be queued for async delivery (behavior may still be synchronous)."
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"async_delivery": False}
                {"async_delivery": True}
            ]
        }
    }
