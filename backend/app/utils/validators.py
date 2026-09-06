from fastapi import HTTPException


def validate_upload_size(
    content: bytes,
    max_size_mb: int,
) -> None:

    max_bytes = max_size_mb * 1024 * 1024

    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"File size exceeds the "
                f"{max_size_mb} MB limit."
            ),
        )


def validate_eml_filename(
    filename: str | None,
) -> None:

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="File name is required.",
        )

    if not filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )