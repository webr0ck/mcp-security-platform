"""Mock Microsoft Graph API stub for AZURE_MODE=mock (PRD-0002 case 1)."""
import os
from fastapi import FastAPI, Request

app = FastAPI(title="Mock Graph API")

@app.get("/v1.0/me")
async def me(request: Request):
    return {
        "id": "mock-user-id",
        "displayName": "Mock User",
        "mail": "mockuser@example.com",
        "userPrincipalName": "mockuser@example.com",
    }

@app.get("/v1.0/me/messages")
async def messages(request: Request):
    return {
        "value": [
            {"id": "msg-001", "subject": "Test email 1", "from": {"emailAddress": {"address": "sender@example.com"}}},
            {"id": "msg-002", "subject": "Test email 2", "from": {"emailAddress": {"address": "sender2@example.com"}}},
        ]
    }

@app.get("/v1.0/users")
async def users(request: Request):
    return {
        "value": [
            {"id": "user-001", "displayName": "Alice Smith", "mail": "alice@example.com"},
            {"id": "user-002", "displayName": "Bob Jones", "mail": "bob@example.com"},
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
