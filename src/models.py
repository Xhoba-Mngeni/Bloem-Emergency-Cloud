from pydantic import BaseModel, field_validator
from typing import Optional, List
import re

# shared properties 
class PatientBase(BaseModel):
    sa_id: str
    first_name: str
    last_name: str
    blood_type: Optional[str] = None
    emergency_contact: Optional[str] = None
    emergency_contact_name: Optional[str] = None
    emergency_contact_surname: Optional[str] = None
    emergency_contact_relationship: Optional[str] = None
    previous_surgeries: Optional[str] = "None"
    allergies: Optional[str] = "None Known"
    consent_status: Optional[str] = "GRANTED" 

    @field_validator('sa_id')
    @classmethod
    def validate_sa_id(cls, v):
        if not re.match(r'^\d{13}$', v):
            raise ValueError('SA ID must be exactly 13 digits')
        return v

# This is for creating input
class PatientCreate(PatientBase):
    condition: Optional[str] = None
    medication: Optional[str] = None

# for reading the output
class PatientResponse(PatientBase):
    is_active: bool

# this is ai safety checks
class SafetyWarning(BaseModel):
    rule_id: Optional[str] = "GENERIC"
    severity: str
    message: str
    reason: Optional[str] = "No detailed reason provided."
    source: Optional[str] = "AI Engine"
    confidence: int = 100

class PatientFullProfile(BaseModel):
    patient: PatientResponse
    medical_history: List[dict]
    current_medications: List[dict]
    ai_safety_analysis: List[SafetyWarning]
