from fastapi import APIRouter, File, HTTPException, UploadFile

from app.schemas.email_schema import EmailAnalysisResponse
from app.services.email.parser import parse_eml


router = APIRouter()


@router.post(
    "/email/upload",
    response_model=EmailAnalysisResponse,
)
async def upload_email(
    file: UploadFile = File(...),
):
    """
    Upload and parse an .eml file.
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

    try:
        parsed_email = parse_eml(content)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return {
        "success": True,
        "filename": file.filename,
        "email": parsed_email,
    }