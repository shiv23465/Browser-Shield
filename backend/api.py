
import traceback

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from urllib.parse import urlsplit

from Core.risk_engine import analyze_url

from backend.database import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_threat_intelligence,
)


app = FastAPI(
    title="Browser Shield | Security API",
    description=(
        "Privacy-conscious URL risk analysis using "
        "Browser Shield's configured detection modules."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {
            "name": "System",
            "description": "API status and service information.",
        },
        {
            "name": "Security Scanner",
            "description": "Analyze URLs with the configured risk engine.",
        },
        {
            "name": "Threat Intelligence",
            "description": "Retrieve saved threat intelligence records.",
        },
    ],
)


# Initialize database when application starts
@app.on_event("startup")
def startup_event():
    initialize_database()


# URL scan request model
class ScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    page_text: str = Field(default="", max_length=50000)
    download_metadata: dict = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:

        value = value.strip()

        try:
            parsed = urlsplit(value)

            valid = (
                parsed.scheme.lower() in ("http", "https")
                and bool(parsed.hostname)
                and not any(char.isspace() for char in value)
                and parsed.username is None
                and parsed.password is None
            )

        except ValueError:
            valid = False

        if not valid:
            raise ValueError(
                "Enter a valid HTTP or HTTPS URL without embedded credentials."
            )

        return value


# Home page
@app.get(
    "/",
    response_class=HTMLResponse,
    include_in_schema=False,
)
def home():

    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Browser Shield | API Portal</title>

      <style>
        * { box-sizing: border-box; }

        body {
          margin: 0;
          background: #0b1120;
          color: #e5edf8;
          font-family: Inter, Segoe UI, Arial, sans-serif;
          line-height: 1.6;
        }

        .container {
          max-width: 1000px;
          margin: auto;
          padding: 32px 22px;
        }

        header {
          display: flex;
          align-items: center;
          gap: 14px;
          padding: 14px 0 28px;
          border-bottom: 1px solid #26334b;
        }

        .logo {
          width: 48px;
          height: 48px;
          display: grid;
          place-items: center;
          border-radius: 14px;
          background: #123b43;
          color: #5eead4;
          font-size: 25px;
          font-weight: 800;
        }

        h1 {
          margin: 0;
          font-size: 24px;
          letter-spacing: -.5px;
        }

        .muted { color: #98a9c2; }

        .status {
          margin-left: auto;
          color: #5eead4;
          background: #123b35;
          padding: 6px 12px;
          border-radius: 20px;
          font-size: 13px;
        }

        .hero { padding: 52px 0 34px; }

        .eyebrow {
          color: #5eead4;
          font-size: 13px;
          font-weight: 700;
        }

        h2 {
          font-size: clamp(30px, 5vw, 46px);
          line-height: 1.15;
          margin: 12px 0;
        }

        .hero p {
          max-width: 660px;
          color: #a9b8ce;
        }

        .grid {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 16px;
        }

        .card {
          background: #121c2e;
          border: 1px solid #28364d;
          border-radius: 16px;
          padding: 22px;
        }

        .card h3 {
          margin: 0 0 8px;
          font-size: 17px;
        }

        .method {
          display: inline-block;
          font-size: 12px;
          font-weight: 800;
          padding: 3px 8px;
          border-radius: 5px;
          background: #153d38;
          color: #5eead4;
          margin-right: 7px;
        }

        code {
          color: #b9c8ff;
          overflow-wrap: anywhere;
        }

        .actions {
          display: flex;
          flex-wrap: wrap;
          gap: 12px;
          margin-top: 26px;
        }

        a.btn {
          display: inline-block;
          text-decoration: none;
          padding: 12px 18px;
          border-radius: 9px;
          font-weight: 700;
          background: #14b8a6;
          color: #062b2a;
        }

        a.secondary {
          background: #18253a;
          color: #e5edf8;
          border: 1px solid #34445e;
        }

        footer {
          margin-top: 36px;
          border-top: 1px solid #26334b;
          padding-top: 20px;
        }

        @media (max-width: 700px) {
          .grid { grid-template-columns: 1fr; }
          .status { font-size: 11px; }
          .hero { padding-top: 36px; }
        }
      </style>
    </head>

    <body>
      <main class="container">

        <header>
          <div class="logo">B</div>

          <div>
            <h1>Browser Shield</h1>
            <div class="muted">Security API Portal</div>
          </div>

          <div class="status">● Service responding</div>
        </header>

        <section class="hero">

          <div class="eyebrow">
            SECURITY ANALYSIS PLATFORM
          </div>

          <h2>
            Understand URL risk.<br>
            Build safer browsing.
          </h2>

          <p>
            Browser Shield provides a REST API for URL risk analysis
            using its configured security detection modules and
            threat intelligence integration.
          </p>

          <div class="actions">
            <a class="btn" href="/docs">Explore API Docs ↗</a>
            <a class="btn secondary" href="/health">Check API Health</a>
            <a class="btn secondary" href="/redoc">ReDoc Reference</a>
          </div>

        </section>

        <section class="grid">

          <article class="card">
            <h3>URL Risk Analysis</h3>
            <p class="muted">
              Submit a URL to receive the configured risk report.
            </p>
            <span class="method">POST</span>
            <code>/scan-url</code>
          </article>

          <article class="card">
            <h3>Health Endpoint</h3>
            <p class="muted">
              Check whether the API process is responding.
            </p>
            <span class="method">GET</span>
            <code>/health</code>
          </article>

          <article class="card">
            <h3>Threat Intelligence</h3>
            <p class="muted">
              Retrieve saved malicious URL intelligence records.
            </p>
            <span class="method">GET</span>
            <code>/threat-intelligence</code>
          </article>

        </section>

        <footer class="muted">
          Browser Shield · Academic cybersecurity project<br>
          Risk results are heuristic findings, not a guarantee of website safety.
        </footer>

      </main>
    </body>
    </html>
    """


# Health endpoint
@app.get(
    "/health",
    tags=["System"],
    summary="Check API health",
)
def health():

    return {
        "status": "healthy",
        "project": "Browser Shield",
    }


# URL scanning endpoint
@app.post(
    "/scan-url",
    tags=["Security Scanner"],
    summary="Analyze and save URL scan",
)
def scan_url(request: ScanRequest):

    try:

        report = analyze_url(
            url=request.url,
            page_text=request.page_text,
            download_metadata=request.download_metadata,
        )

        history_data = {
            **report,
            "url": request.url,
        }

        saved_record = save_scan(history_data)

        return {
            **report,
            "scan_id": saved_record["id"],
            "scanned_at": saved_record["scanned_at"],
        }

    except Exception:

        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail="URL analysis or history saving failed.",
        )


# Scan history endpoint
@app.get(
    "/scan-history",
    tags=["Security Scanner"],
    summary="Get recent URL scan history",
)
def scan_history(limit: int = 50):

    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100.",
        )

    try:

        records = get_scan_history(limit)

        return {
            "total": len(records),
            "scans": records,
        }

    except Exception:

        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve scan history.",
        )


# Threat intelligence endpoint
@app.get(
    "/threat-intelligence",
    tags=["Threat Intelligence"],
    summary="Get saved threat intelligence records",
)
def threat_intelligence(limit: int = 100):

    if not 1 <= limit <= 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500.",
        )

    try:

        records = get_threat_intelligence(limit)

        return {
            "project": "Browser Shield",
            "total": len(records),
            "threats": records,
        }

    except Exception:

        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve threat intelligence records.",
        )
