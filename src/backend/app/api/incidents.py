from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Incident
from app.schemas import IncidentCreate, IncidentRead

router = APIRouter(prefix="/incidents", tags=["incidents"])
DB_SESSION = Depends(get_db)


@router.post("", response_model=IncidentRead)
def create_incident(payload: IncidentCreate, db: Session = DB_SESSION) -> Incident:
    incident = Incident(title=payload.title, description=payload.description)
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentRead)
def get_incident(incident_id: int, db: Session = DB_SESSION) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
