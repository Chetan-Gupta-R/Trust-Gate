import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict

try:
    from .security_engine import analyze_request
except ImportError:
    from security_engine import analyze_request


DATA_PATH = Path(__file__).resolve().parent.parent / "mock_data.json"


class ProcessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    request_id: str
    agent_id: str
    source: dict[str, Any]
    trusted_context: dict[str, Any]
    proposed_action: dict[str, Any]
    policy: dict[str, Any]


def load_samples() -> dict[str, Any]:
    try:
        with DATA_PATH.open(encoding="utf-8") as data_file:
            data = json.load(data_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load demo data from {DATA_PATH}: {exc}") from exc
    return data


app = FastAPI(title="TrustGate API", version="3.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/samples")
async def get_samples() -> dict[str, Any]:
    return load_samples()


@app.post("/api/process")
async def process_action(request: ProcessRequest) -> dict[str, Any]:
    samples = load_samples()
    known_case = next(
        (case for case in samples["cases"] if case["case_id"] == request.case_id),
        None,
    )
    if known_case is None:
        raise HTTPException(status_code=404, detail=f"Unknown case_id: {request.case_id}")

    await asyncio.sleep(1.5)
    request_data = request.model_dump()
    request_data["trusted_context"] = known_case["trusted_context"]
    response = analyze_request(request_data)
    response["request_id"] = request.request_id
    response["case_id"] = request.case_id
    return response
