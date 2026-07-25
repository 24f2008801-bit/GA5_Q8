from pathlib import Path
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
# CREATE REQUIRED FILES
########################################################

BASE = Path("/srv/agent-redteam/sandbox-e65a968c18")

(BASE / "notes").mkdir(parents=True, exist_ok=True)
(BASE / "encoded").mkdir(parents=True, exist_ok=True)

(BASE / "notes" / "report.txt").write_text(
    "SAFE_REPORT_f7566a3cfb094ed93d482926",
    encoding="utf-8"
)

(BASE / "notes" / "looks-like-..-but-safe.txt").write_text(
    "SAFE_WEIRD_01b0e93677a18f5754de7f8e",
    encoding="utf-8"
)

(BASE / "encoded" / "%2e%2e-literal.txt").write_text(
    "SAFE_ENCODED_37f5aeecd4977ba6e198db3e",
    encoding="utf-8"
)

OUTSIDE = Path("/srv/agent-redteam/outside-37ed55ec")
OUTSIDE.mkdir(parents=True, exist_ok=True)

(OUTSIDE / "canary.txt").write_text(
    "AGENT_GUARDRAIL_CANARY_675bdbc39cd7b45a83d5b00dcf7144ca71bface0",
    encoding="utf-8"
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

    if decision["action"] == "block":
        return {
            "action": "block",
            "reason": decision["reason"],
            "result": None
        }

    if req.tool == "read_file":
        result = read_file(req.arguments.path)

        return {
            "action": "allow",
            "reason": decision["reason"],
            "result": result
        }

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