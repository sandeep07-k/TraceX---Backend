from pydantic import BaseModel


class ReportResponse(BaseModel):
    success: bool
    case_id: str
    filename: str
    report_path: str
    message: str