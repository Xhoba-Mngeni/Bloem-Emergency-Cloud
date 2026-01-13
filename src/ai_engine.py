import json
import os
from fuzzywuzzy import process

#  Constants for severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MED = "MEDIUM"
SEVERITY_SAFE = "SAFE"

# Load Knowledge Base
def load_knowledge_base():
    try:
        json_path = os.path.join(os.path.dirname(__file__), 'knowledge_base.json')
        with open(json_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading knowledge base: {e}")
        return {"interactions": [], "valid_medications": []}

KB = load_knowledge_base()
INTERACTIONS = KB.get("interactions", [])
VALID_MEDICATIONS = KB.get("valid_medications", [])

def normalize_text(text: str) -> str:
    """Standardizes text: lowercase, strips whitespace."""
    if not text:
        return ""
    return text.lower().strip()

def analyze_patient_safety(history: list, current_meds: list, patient_allergies: str):
    warnings = []
    
    # Normalize Patient Data
    clean_allergies = normalize_text(patient_allergies)
    
    # Extract condition names from history
    patient_conditions = [normalize_text(h['name']) for h in history]
    
    # 1. typo correction and normalization of current meds
    # Create a list of normalized current meds
    normalized_meds = []
    
    for med in current_meds:
        original_name = med['name']
        clean_med_name = normalize_text(original_name)

        # Fuzzy Match against the Valid Meds
        best_match = None
        score = 0
        
        if VALID_MEDICATIONS:
            result = process.extractOne(original_name, VALID_MEDICATIONS)
            if result:
                best_match, score = result
        
        if score > 80:
            if score < 100:
                 warnings.append({
                    "rule_id": "TYPO_001",
                    "severity": SEVERITY_MED,
                    "message": f"Did you mean '{best_match}' instead of '{original_name}'?",
                    "reason": "Potential medication spelling error detected.",
                    "source": "AI Typo Engine",
                    "confidence": score
                })
            # Use corrected name
            normalized_meds.append(normalize_text(best_match))
        else:
            # Keep original if no match found or low confidence
            normalized_meds.append(clean_med_name)

    # 2. Where interactions are being checked 
    for rule in INTERACTIONS:
        condition_key = normalize_text(rule['condition_keyword'])
        
        # Check if patient has this condition or allergy
        # We check both history and allergy field against the condition_keyword
        has_condition = (condition_key in patient_conditions)
        has_allergy = (clean_allergies and condition_key in clean_allergies)
        
        if has_condition or has_allergy:
            
            # Check Risky Meds
            if "risky_meds" in rule:
                for risky in rule["risky_meds"]:
                    clean_risky = normalize_text(risky)
                    # Check if any patient med contains the risky ingredient or something like that
                    # We use simple string inclusion check
                    for pat_med in normalized_meds:
                        if clean_risky in pat_med:
                            warnings.append({
                                "rule_id": "INTERACTION_002",
                                "severity": rule.get("severity", SEVERITY_HIGH),
                                "message": rule.get("message", f"Interaction detected with {rule['condition_keyword']}"),
                                "reason": rule.get("reason", "Contraindicated for patient condition/allergy."),
                                "source": rule.get("source", "Medical Guidelines"),
                                "confidence": 100
                            })
                            
            # Check Required Meds (e.g. for HIV, Diabetes, etc.)
            # Logic: If condition exists, ensure at least ONE of the required meds is present
            if "required_meds" in rule:
                required = [normalize_text(m) for m in rule["required_meds"]]
                # Check if any required med is loosely matched in normalized meds
                found = False
                for req in required:
                    for med in normalized_meds:
                        if req in med:
                            found = True
                            break
                    if found:
                        break
                
                if not found:
                     warnings.append({
                        "rule_id": "MISSING_MED_003",
                        "severity": rule.get("severity", "CRITICAL"),
                        "message": rule.get("message", f"Missing required medication for {rule['condition_keyword']}"),
                        "reason": rule.get("reason", "Standard of care requires medication adherence."),
                        "source": rule.get("source", "Medical Guidelines"),
                        "confidence": 100
                    })

    # Calculate Overall Risk Level
    risk_level = SEVERITY_SAFE
    for w in warnings:
        sev = w.get("severity", "LOW")
        if sev in [SEVERITY_CRITICAL, SEVERITY_HIGH]:
            risk_level = "HIGH"
            break
        elif sev == SEVERITY_MED and risk_level != "HIGH":
            risk_level = "MEDIUM"

    return {
        "risk_level": risk_level,
        "warnings": warnings
    }
