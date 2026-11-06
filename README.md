# TrustGate

**Don't let strangers give your AI orders.**

TrustGate is a lightweight AI agent action security gateway demo. Its deterministic backend independently checks proposed invoice payments against trusted vendor data and policy. Untrusted invoice text is inspected for common prompt-injection patterns; no LLM is used to authorize actions and no payments are executed.

## Project structure

```text
TrustGate/
├── mock_data.json
├── backend/
│   ├── main.py
│   ├── security_engine.py
│   ├── injection_detector.py
│   ├── policy_engine.py
│   ├── test_security_engine.py
│   ├── requirements.txt
│   └── requirements-dev.txt
└── frontend/
    ├── public/
    │   └── mock_data.json
    ├── src/
    │   ├── App.jsx
    │   ├── main.jsx
    │   └── index.css
    ├── index.html
    ├── package.json
    ├── postcss.config.js
    ├── tailwind.config.js
    └── vite.config.js
```

## Requirements

- Python 3.10+
- Node.js 20.19+ (or 22.12+)
- npm

## Run the backend

From the project root:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

If PowerShell blocks activation, allow it for the current terminal with:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
```

macOS/Linux activation:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Backend API docs: <http://localhost:8000/docs>

## Run the frontend

In a second terminal, from the project root:

```powershell
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173>.

## Demo cases and offline mode

The dashboard has three dynamically populated cases: a normal invoice, a critical prompt injection and beneficiary mismatch, and a low-value matching invoice. The backend simulates 1.5 seconds of analysis and calculates the decision from the request and trusted vendor record. Stored `expected_response` values are used only by the frontend's offline fallback.

If the backend is offline, the frontend loads sample data and expected results from `frontend/public/mock_data.json` and marks analyzed decisions as a **LOCAL DEMO FALLBACK**. This demo does not initiate payments.

The detector uses case-insensitive pattern matching on normalized document text. It is a deterministic demo detector for common malicious instructions, not a guarantee of complete prompt-injection protection. The server enforces a ₹10,000 automatic payment ceiling and essential checks even if the request supplies a more permissive policy.

The API uses the matching case's backend-stored trusted vendor record; it does not trust a client-supplied replacement. Risk points are explainable and capped at 100: prompt injection +38, concealment +20, beneficiary mismatch +25, vendor verification failure +30, amount above limit +15, invalid/unsupported action +40, and missing invoice text +30. Labels are LOW (0–19), MEDIUM (20–49), HIGH (50–79), and CRITICAL (80–100). The response includes a per-factor breakdown.

## Run backend tests

```powershell
cd backend
pip install -r requirements-dev.txt
python -m pytest -q
```

## API contract

- `GET /api/samples` returns persona, shared policy, and all sample cases.
- `POST /api/process` accepts `case_id`, `request_id`, `agent_id`, `source`, `trusted_context`, `proposed_action`, and `policy`. Its response contains the deterministic decision, risk analysis, policy checks, execution status, and evidence.
- Unknown case IDs return HTTP 404. Invalid request shapes are rejected by FastAPI/Pydantic.
