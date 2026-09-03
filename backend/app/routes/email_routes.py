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

    return {
        "success": True,
        "filename": file.filename,
        "email": parsed_email,
        "header_forensics": header_forensics,
        "authentication": authentication,
        "threat_analysis": threat_analysis,
    }

    