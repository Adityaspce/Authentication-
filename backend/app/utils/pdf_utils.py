# pdf_utils.py
from io import BytesIO
import PyPDF2

def extract_metadata(file_bytes: bytes) -> dict:
    """
    Simple PDF metadata extractor.
    Returns dictionary with title, author, number of pages, etc.
    """
    reader = PyPDF2.PdfReader(BytesIO(file_bytes))
    info = reader.metadata
    metadata = {
        "title": info.title if info.title else "",
        "author": info.author if info.author else "",
        "subject": info.subject if info.subject else "",
        "producer": info.producer if info.producer else "",
        "num_pages": len(reader.pages)
    }
    return metadata
