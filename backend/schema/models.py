from pydantic import BaseModel
from typing import Optional

class DocumentMetadata(BaseModel):
    filename: str
    file_type: str
    file_size: int
    author: Optional[str] = None
    creation_date: Optional[str] = None
    producer: Optional[str] = None

class PayloadRequest(BaseModel):
    user_prompt: str
    document_text: Optional[str] = None
    document_metadata: Optional[DocumentMetadata] = None

class RiskAnalysisResponse(BaseModel):
    risk_score: float
    risk_level: str
    detected_intent: str
    reasoning: str
    atlas_technique_id: Optional[str] = None
    impact: str
    mitigation_action: str
    analysis_layer: Optional[str] = "N/A"