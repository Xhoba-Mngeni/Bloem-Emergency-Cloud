import sys
import os
import unittest

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from ai_engine import analyze_patient_safety

class TestAIEngine(unittest.TestCase):
    def test_asthma_beta_blocker(self):
        history = [{"name": "Asthma", "date": "2020-01-01"}]
        meds = [{"name": "Propranolol", "dosage": "10mg"}]
        allergies = "None"
        
        result = analyze_patient_safety(history, meds, allergies)
        warnings = result['warnings']
        found = any("Bronchospasm" in w['message'] for w in warnings)
        self.assertTrue(found, "Should detect Asthma <-> Propranolol interaction")

    def test_typo_correction(self):
        history = []
        meds = [{"name": "Propanolol", "dosage": "10mg"}]
        allergies = "None"
        
        result = analyze_patient_safety(history, meds, allergies)
        warnings = result['warnings']
        found = any("Did you mean 'Propranolol'" in w['message'] for w in warnings)
        self.assertTrue(found, "Should detect typo Propanolol -> Propranolol")

    def test_hiv_missing_meds(self):
        history = [{"name": "HIV Positive", "date": "2020-01-01"}]
        meds = [{"name": "Panado", "dosage": "10mg"}] 
        allergies = "None"
        
        result = analyze_patient_safety(history, meds, allergies)
        warnings = result['warnings']
        found = any("adherence" in w['message'] or "Missing required" in w['message'] for w in warnings)
        self.assertTrue(found, "Should detect missing ARVs for HIV patient")

    def test_peanut_allergy(self):
        history = []
        meds = [{"name": "Peanut Oil Cream", "dosage": "10mg"}]
        allergies = "Peanuts"
        
        result = analyze_patient_safety(history, meds, allergies)
        warnings = result['warnings']
        found = any("ANAPHYLAXIS" in w['message'] for w in warnings)
        self.assertTrue(found, "Should detect Peanut Allergy")

if __name__ == '__main__':
    unittest.main()
