from fastapi import APIRouter, File, HTTPException, UploadFile

from app.schemas.email_schema import EmailAnalysisResponse
from app.services.email.header_analyzer import analyze_headers
from app.services.email.parser import parse_eml

from app.services.email.authentication_analyzer import (
    analyze_authentication,
)
from app.services.threat.threat_analyzer import (
    analyze_threats,
)
from app.services.risk.risk_engine import (
    calculate_risk,
)
from app.services.ai.ai_analyzer import (
    analyze_email_with_ai,
)
from app.services.intelligence.intelligence_analyzer import (
    analyze_intelligence,
)
from app.services.forensic.relay_tracer import (
    trace_relay_path,
)
from app.services.forensic.correlation_engine import (
    correlate_entities,
)

from app.services.forensic.graph_builder import (
    build_forensic_graph,
)
from app.services.case.case_service import (
    create_case,
    save_analysis,
)
router = APIRouter()


@router.post(
    "/email/upload",
    response_model=EmailAnalysisResponse,
)
async def upload_email(
    file: UploadFile = File(...),
):
    """
    Upload and analyze an .eml file.
    """

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File name is required.",
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    content = await file.read()

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty.",
        )

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
            detail=f"Email analysis failed: {exc}",
        ) from exc

    parsed_email = parse_eml(content)

    header_forensics = analyze_headers(
        parsed_email
    )

    authentication = analyze_authentication(
        parsed_email
    )

    parsed_email = parse_eml(content)

    header_forensics = analyze_headers(
        parsed_email
    )

    authentication = analyze_authentication(
        parsed_email
    )

    threat_analysis = analyze_threats(
        parsed_email,
        header_forensics,
    )

    parsed_email = parse_eml(content)

    header_forensics = analyze_headers(
        parsed_email
    )

    authentication = analyze_authentication(
        parsed_email
    )

    threat_analysis = analyze_threats(
        parsed_email,
        header_forensics,
    )

    
    parsed_email = parse_eml(content)

    header_forensics = analyze_headers(
        parsed_email
    )

    authentication = analyze_authentication(
        parsed_email
    )

    threat_analysis = analyze_threats(
        parsed_email,
        header_forensics,
    )
    ai_analysis = analyze_email_with_ai(
        parsed_email
    )

    risk = calculate_risk(
        header_forensics,
        authentication,
        threat_analysis,
        ai_analysis,
    )

    intelligence = analyze_intelligence(
      parsed_email
    )

    relay_trace = trace_relay_path(
        parsed_email.get(
            "received_headers",
            [],
        )
    )

    correlation = correlate_entities(
        intelligence,
        relay_trace,
        header_forensics,
    )

    forensic_graph = build_forensic_graph(
        parsed_email,
        intelligence,
        relay_trace,
    )

    case = create_case(
    title=(
            parsed_email.get(
                "subject"
            )
            or "Email Investigation"
        )
    )
    analysis_result = {
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

    save_analysis(
        case["case_id"],
        analysis_result,
    )

    return {
        "success": True,
        "case_id": case["case_id"],
        "filename": file.filename,
        **analysis_result,
    }

    return {
        "success": True,
        "filename": file.filename,
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

    