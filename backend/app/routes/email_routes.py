from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from app.schemas.email_schema import EmailAnalysisResponse

from app.services.email.header_analyzer import analyze_headers
from app.services.email.parser import parse_eml
from app.services.email.authentication_analyzer import analyze_authentication

from app.services.threat.threat_analyzer import analyze_threats
from app.services.risk.risk_engine import calculate_risk
from app.services.ai.ai_analyzer import analyze_email_with_ai
from app.services.intelligence.intelligence_analyzer import analyze_intelligence

from app.services.forensic.relay_tracer import trace_relay_path
from app.services.forensic.correlation_engine import correlate_entities
from app.services.forensic.graph_builder import build_forensic_graph

from app.services.case.case_service import create_case, save_analysis

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config.settings import settings
from app.utils.security import safe_filename
from app.utils.validators import (
    validate_eml_filename,
    validate_upload_size,
)


limiter = Limiter(
    key_func=get_remote_address
)

router = APIRouter()


@router.post(
    "/email/upload",
    response_model=EmailAnalysisResponse,
)
@limiter.limit(settings.rate_limit)
async def upload_email(
    request: Request,
    file: UploadFile = File(...),
):
    """
    Upload and analyze an .eml file.
    """

    # -------------------------------------------------
    # PHASE 12: SECURITY VALIDATION
    # -------------------------------------------------

    # Validate filename
    validate_eml_filename(file.filename)

    # Read uploaded file ONCE
    content = await file.read()

    # Check empty file
    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty.",
        )

    # Validate file size
    validate_upload_size(
        content,
        settings.max_upload_size_mb,
    )

    # Sanitize filename
    filename = safe_filename(
        file.filename
    )

    # -------------------------------------------------
    # EMAIL PARSING
    # -------------------------------------------------

    try:
        parsed_email = parse_eml(content)

        header_forensics = analyze_headers(
            parsed_email
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Email analysis failed.",
        ) from exc

    # -------------------------------------------------
    # AUTHENTICATION ANALYSIS
    # -------------------------------------------------

    authentication = analyze_authentication(
        parsed_email
    )

    # -------------------------------------------------
    # THREAT ANALYSIS
    # -------------------------------------------------

    threat_analysis = analyze_threats(
        parsed_email,
        header_forensics,
    )

    # -------------------------------------------------
    # AI ANALYSIS
    # -------------------------------------------------

    ai_analysis = analyze_email_with_ai(
        parsed_email
    )

    # -------------------------------------------------
    # RISK ENGINE
    # -------------------------------------------------

    risk = calculate_risk(
        header_forensics,
        authentication,
        threat_analysis,
        ai_analysis,
    )

    # -------------------------------------------------
    # THREAT INTELLIGENCE
    # -------------------------------------------------

    intelligence = analyze_intelligence(
        parsed_email
    )

    # -------------------------------------------------
    # RELAY TRACE
    # -------------------------------------------------

    relay_trace = trace_relay_path(
        parsed_email.get(
            "received_headers",
            [],
        )
    )

    # -------------------------------------------------
    # CORRELATION
    # -------------------------------------------------

    correlation = correlate_entities(
        intelligence,
        relay_trace,
        header_forensics,
    )

    # -------------------------------------------------
    # FORENSIC GRAPH
    # -------------------------------------------------

    forensic_graph = build_forensic_graph(
        parsed_email,
        intelligence,
        relay_trace,
    )

    # -------------------------------------------------
    # CASE MANAGEMENT
    # -------------------------------------------------

    case = create_case(
        title=(
            parsed_email.get("subject")
            or "Email Investigation"
        )
    )

    # -------------------------------------------------
    # FINAL ANALYSIS RESULT
    # -------------------------------------------------

    analysis_result = {
        "source_filename": filename,
        "email": parsed_email,
        "header_forensics": header_forensics,
        "authentication": authentication,
        "threat_analysis": threat_analysis,
        "risk": risk,
        "ai_analysis": ai_analysis,
        "intelligence": intelligence,
        "relay_trace": relay_trace,
        "correlation": correlation,
        "forensic_graph": forensic_graph,
    }

    # -------------------------------------------------
    # SAVE ANALYSIS
    # -------------------------------------------------

    save_analysis(
        case["case_id"],
        analysis_result,
    )

    # -------------------------------------------------
    # RESPONSE
    # -------------------------------------------------

    return {
        "success": True,
        "case_id": case["case_id"],
        "filename": filename,
        **analysis_result,
    }