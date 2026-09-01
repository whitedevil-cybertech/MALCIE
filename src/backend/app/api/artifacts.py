from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Artifact
from app.schemas import ArtifactAnalysisRead
from app.services.pe_static_analysis import analyze_artifact, persist_artifact_analysis

router = APIRouter(prefix="/artifacts", tags=["artifacts"])
DB_SESSION = Depends(get_db)


@router.post("/{artifact_id}/analyze-static", response_model=ArtifactAnalysisRead)
def analyze_static_artifact(artifact_id: int, db: Session = DB_SESSION):
    artifact = db.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")

    analysis = analyze_artifact(artifact)
    record = persist_artifact_analysis(artifact=artifact, analysis=analysis)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/{artifact_id}/analysis-static", response_model=ArtifactAnalysisRead)
def get_static_analysis(artifact_id: int, db: Session = DB_SESSION):
    artifact = db.get(Artifact, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    if artifact.analysis is None:
        raise HTTPException(status_code=404, detail="Static analysis not found")
    return artifact.analysis
