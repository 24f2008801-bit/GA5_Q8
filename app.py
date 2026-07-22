from fastapi import FastAPI
from pydantic import BaseModel
from typing import Literal

from executor import read_file, fetch_url
from redteam_guard import evaluate_request

app = FastAPI(
    title="GA5 Q8 Red Team Guardrail",
    version="1.0"
)

########################################################
# Models
########################################################

class ToolArguments(BaseModel):
    path: str | None = None
    url: str | None = None


class RedTeamRequest(BaseModel):
    tool: Literal["read_file", "fetch_url"]
    arguments: ToolArguments


########################################################
# Endpoint
########################################################

@app.post("/redteam")
def redteam(req: RedTeamRequest):

    request = req.model_dump()

    decision = evaluate_request(request)

    # Block
    if decision["action"] == "block":
        return {
            "action": "block",
            "reason": decision["reason"],
            "result": None
        }

    # Execute read_file
    if req.tool == "read_file":
        result = read_file(req.arguments.path)

        return {
            "action": "allow",
            "reason": decision["reason"],
            "result": result
        }

    # Execute fetch_url
    if req.tool == "fetch_url":
        result = fetch_url(req.arguments.url)

        return {
            "action": "allow",
            "reason": decision["reason"],
            "result": result
        }

    return {
        "action": "block",
        "reason": "Unknown tool.",
        "result": None
    }


########################################################
# Root
########################################################

@app.get("/")
def root():
    return {
        "message": "GA5 Q8 Red Team Running"
    }