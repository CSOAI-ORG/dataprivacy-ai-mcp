"""
DataPrivacy.AI MCP Server - GDPR & Privacy Compliance
Built by MEOK AI Labs | https://dataprivacyof.ai

GDPR personal data classification, lawful basis assessment, DPIA generation,
international data transfer checks, breach severity scoring, and privacy
notice generation. Covers UK GDPR and EU GDPR.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "dataprivacy-ai")

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_RATE_LIMITS = {
    "free": {"requests_per_hour": 60},
    "pro": {"requests_per_hour": 10000},
}
_request_log: list[float] = []
_tier = "free"


def _check_rate_limit() -> bool:
    now = time.time()
    _request_log[:] = [t for t in _request_log if now - t < 3600]
    if len(_request_log) >= _RATE_LIMITS[_tier]["requests_per_hour"]:
        return False
    _request_log.append(now)
    return True


# ---------------------------------------------------------------------------
# Personal data categories (GDPR Article 4 and Article 9)
# ---------------------------------------------------------------------------
_DATA_CATEGORIES = {
    # Standard personal data (Article 4(1))
    "name": {"category": "personal", "article": "4(1)", "description": "Name of a natural person"},
    "full_name": {"category": "personal", "article": "4(1)", "description": "Full name of a natural person"},
    "first_name": {"category": "personal", "article": "4(1)", "description": "First/given name"},
    "last_name": {"category": "personal", "article": "4(1)", "description": "Family/surname"},
    "email": {"category": "personal", "article": "4(1)", "description": "Email address - direct identifier"},
    "email_address": {"category": "personal", "article": "4(1)", "description": "Email address - direct identifier"},
    "phone": {"category": "personal", "article": "4(1)", "description": "Phone number - direct identifier"},
    "phone_number": {"category": "personal", "article": "4(1)", "description": "Phone number - direct identifier"},
    "address": {"category": "personal", "article": "4(1)", "description": "Physical address"},
    "postal_address": {"category": "personal", "article": "4(1)", "description": "Postal address"},
    "date_of_birth": {"category": "personal", "article": "4(1)", "description": "Date of birth - quasi-identifier"},
    "dob": {"category": "personal", "article": "4(1)", "description": "Date of birth - quasi-identifier"},
    "age": {"category": "personal", "article": "4(1)", "description": "Age - quasi-identifier (may identify in combination)"},
    "national_insurance_number": {"category": "personal", "article": "4(1)", "description": "UK National Insurance Number - unique identifier"},
    "ni_number": {"category": "personal", "article": "4(1)", "description": "UK National Insurance Number - unique identifier"},
    "social_security_number": {"category": "personal", "article": "4(1)", "description": "Social security number - unique identifier"},
    "ssn": {"category": "personal", "article": "4(1)", "description": "Social security number - unique identifier"},
    "passport_number": {"category": "personal", "article": "4(1)", "description": "Passport number - unique identifier"},
    "driving_licence": {"category": "personal", "article": "4(1)", "description": "Driving licence number - unique identifier"},
    "ip_address": {"category": "personal", "article": "4(1), Recital 30", "description": "IP address - online identifier"},
    "cookie_id": {"category": "personal", "article": "4(1), Recital 30", "description": "Cookie identifier - online identifier"},
    "device_id": {"category": "personal", "article": "4(1), Recital 30", "description": "Device identifier - online identifier"},
    "location_data": {"category": "personal", "article": "4(1)", "description": "Location/GPS data - can identify movements and habits"},
    "gps": {"category": "personal", "article": "4(1)", "description": "GPS coordinates - location data"},
    "bank_account": {"category": "personal", "article": "4(1)", "description": "Bank account details - financial identifier"},
    "credit_card": {"category": "personal", "article": "4(1)", "description": "Credit/debit card number - financial identifier"},
    "salary": {"category": "personal", "article": "4(1)", "description": "Salary/income information"},
    "photograph": {"category": "personal", "article": "4(1), 4(14)", "description": "Photograph - biometric data if used for identification"},
    "vehicle_registration": {"category": "personal", "article": "4(1)", "description": "Vehicle registration number - linked to keeper"},
    "employee_id": {"category": "personal", "article": "4(1)", "description": "Employee identifier - identifies within organisation"},
    "customer_id": {"category": "personal", "article": "4(1)", "description": "Customer identifier"},
    "username": {"category": "personal", "article": "4(1)", "description": "Username/login identifier"},

    # Special category data (Article 9)
    "racial_origin": {"category": "special", "article": "9(1)", "description": "Racial or ethnic origin - special category"},
    "ethnic_origin": {"category": "special", "article": "9(1)", "description": "Ethnic origin - special category"},
    "ethnicity": {"category": "special", "article": "9(1)", "description": "Ethnicity - special category"},
    "race": {"category": "special", "article": "9(1)", "description": "Racial origin - special category"},
    "political_opinion": {"category": "special", "article": "9(1)", "description": "Political opinions - special category"},
    "political_affiliation": {"category": "special", "article": "9(1)", "description": "Political affiliation - special category"},
    "religion": {"category": "special", "article": "9(1)", "description": "Religious beliefs - special category"},
    "religious_belief": {"category": "special", "article": "9(1)", "description": "Religious beliefs - special category"},
    "philosophical_belief": {"category": "special", "article": "9(1)", "description": "Philosophical beliefs - special category"},
    "trade_union": {"category": "special", "article": "9(1)", "description": "Trade union membership - special category"},
    "trade_union_membership": {"category": "special", "article": "9(1)", "description": "Trade union membership - special category"},
    "genetic_data": {"category": "special", "article": "9(1), 4(13)", "description": "Genetic data - special category"},
    "dna": {"category": "special", "article": "9(1), 4(13)", "description": "DNA/genetic data - special category"},
    "biometric_data": {"category": "special", "article": "9(1), 4(14)", "description": "Biometric data for identification - special category"},
    "fingerprint": {"category": "special", "article": "9(1), 4(14)", "description": "Fingerprint - biometric/special category"},
    "facial_recognition": {"category": "special", "article": "9(1), 4(14)", "description": "Facial recognition data - biometric/special category"},
    "health_data": {"category": "special", "article": "9(1), 4(15)", "description": "Health data - special category"},
    "medical_record": {"category": "special", "article": "9(1), 4(15)", "description": "Medical records - health/special category"},
    "disability": {"category": "special", "article": "9(1), 4(15)", "description": "Disability status - health/special category"},
    "mental_health": {"category": "special", "article": "9(1), 4(15)", "description": "Mental health data - special category"},
    "sexual_orientation": {"category": "special", "article": "9(1)", "description": "Sexual orientation - special category"},
    "sex_life": {"category": "special", "article": "9(1)", "description": "Data concerning sex life - special category"},
    "gender_identity": {"category": "special", "article": "9(1)", "description": "Gender identity - may fall under special category"},

    # Criminal data (Article 10)
    "criminal_conviction": {"category": "criminal", "article": "10", "description": "Criminal convictions - Article 10 data, requires specific authority"},
    "criminal_record": {"category": "criminal", "article": "10", "description": "Criminal record data - Article 10"},
    "dbs_check": {"category": "criminal", "article": "10", "description": "DBS check result - criminal offence data"},
    "caution": {"category": "criminal", "article": "10", "description": "Police caution - criminal offence data"},

    # Anonymous / not personal
    "aggregate_statistics": {"category": "anonymous", "article": "Recital 26", "description": "Aggregated statistics - not personal data if truly anonymous"},
    "anonymised_data": {"category": "anonymous", "article": "Recital 26", "description": "Anonymised data - not personal data (irreversible)"},
    "company_name": {"category": "not_personal", "article": "N/A", "description": "Company name - legal persons are not data subjects under GDPR"},
    "company_registration": {"category": "not_personal", "article": "N/A", "description": "Company registration number - not personal data"},
    "vat_number": {"category": "not_personal", "article": "N/A", "description": "VAT number - not personal data (unless sole trader)"},
}

# ---------------------------------------------------------------------------
# Lawful bases (Article 6)
# ---------------------------------------------------------------------------
_LAWFUL_BASES = {
    "consent": {
        "article": "6(1)(a)",
        "name": "Consent",
        "description": "The data subject has given consent to the processing for one or more specific purposes.",
        "requirements": [
            "Must be freely given, specific, informed, and unambiguous (Article 4(11))",
            "Must be an affirmative action (pre-ticked boxes are NOT valid consent)",
            "Must be as easy to withdraw as to give (Article 7(3))",
            "Controller must be able to demonstrate consent was given (Article 7(1))",
            "Children under 13 (UK) / 16 (EU) require parental consent for online services (Article 8)",
            "Cannot be bundled with T&Cs as condition of service if not necessary",
            "Separate consent needed for each distinct purpose",
        ],
        "when_appropriate": [
            "Marketing emails/communications",
            "Non-essential cookies and tracking",
            "Sharing data with third parties for their own purposes",
            "Processing special category data (alongside Article 9 condition)",
            "Research where no other basis applies",
        ],
        "risks": [
            "Can be withdrawn at any time - must stop processing",
            "Power imbalance may invalidate consent (e.g. employer/employee)",
            "High administrative burden to manage consent records",
        ],
    },
    "contract": {
        "article": "6(1)(b)",
        "name": "Performance of a Contract",
        "description": "Processing is necessary for the performance of a contract with the data subject, or to take pre-contractual steps at their request.",
        "requirements": [
            "A contract must exist (or data subject requests pre-contractual steps)",
            "Processing must be NECESSARY for the contract, not merely useful",
            "Cannot use for purposes beyond what the contract requires",
        ],
        "when_appropriate": [
            "Delivering goods/services ordered by the customer",
            "Processing payment for a purchase",
            "Providing a quote requested by the individual",
            "Employee payroll processing (employment contract)",
            "Account management for a service subscription",
        ],
        "risks": [
            "Narrow scope - only covers what is genuinely necessary for the contract",
            "Cannot rely on this for marketing even to existing customers",
        ],
    },
    "legal_obligation": {
        "article": "6(1)(c)",
        "name": "Legal Obligation",
        "description": "Processing is necessary for compliance with a legal obligation to which the controller is subject.",
        "requirements": [
            "Must be a clear legal obligation (not just industry guidance)",
            "The obligation must be in UK or EU law",
            "Must be able to identify the specific legal provision",
        ],
        "when_appropriate": [
            "Tax reporting to HMRC",
            "Employment law record-keeping",
            "Anti-money laundering (AML) checks",
            "Health and safety incident reporting",
            "Responding to court orders or statutory requests",
            "Right to work checks (Immigration Act 2006)",
        ],
        "risks": [
            "Limited to what the law specifically requires",
            "Cannot use as catch-all for regulatory compliance",
        ],
    },
    "vital_interests": {
        "article": "6(1)(d)",
        "name": "Vital Interests",
        "description": "Processing is necessary to protect the vital interests (life or death) of the data subject or another person.",
        "requirements": [
            "Must be a genuine life-threatening situation",
            "Cannot rely on this if another lawful basis is available",
            "Rarely applicable - last resort basis",
        ],
        "when_appropriate": [
            "Medical emergency where patient cannot consent",
            "Natural disaster victim identification",
            "Safeguarding in immediate danger situations",
        ],
        "risks": [
            "Very narrow scope - essentially life or death only",
            "ICO guidance: should not be used routinely",
        ],
    },
    "public_task": {
        "article": "6(1)(e)",
        "name": "Public Task",
        "description": "Processing is necessary for the performance of a task carried out in the public interest or in the exercise of official authority.",
        "requirements": [
            "Must have a clear basis in law for the public task",
            "Processing must be necessary (not merely convenient)",
            "Mainly for public authorities and bodies with statutory functions",
        ],
        "when_appropriate": [
            "Local authority functions (planning, social services, etc.)",
            "NHS patient record management",
            "Police and law enforcement processing",
            "Universities conducting research in the public interest",
            "Regulators exercising statutory powers",
        ],
        "risks": [
            "Data subjects have right to object (Article 21)",
            "Must conduct balancing test if objection received",
        ],
    },
    "legitimate_interests": {
        "article": "6(1)(f)",
        "name": "Legitimate Interests",
        "description": "Processing is necessary for the legitimate interests of the controller or a third party, except where overridden by the interests, rights, and freedoms of the data subject.",
        "requirements": [
            "Must conduct a Legitimate Interests Assessment (LIA) - three-part test",
            "1. Purpose test: Is there a legitimate interest? (business, third party, or wider benefit)",
            "2. Necessity test: Is the processing necessary for that interest? (no less intrusive way?)",
            "3. Balancing test: Do the individual's interests override the legitimate interest?",
            "Document the LIA and keep it under review",
            "NOT available to public authorities for their core tasks (use public task instead)",
        ],
        "when_appropriate": [
            "Fraud prevention and detection",
            "Network and information security",
            "Direct marketing to existing customers (soft opt-in)",
            "Intra-group transfers for administrative purposes",
            "Processing necessary to ensure physical security (CCTV)",
            "Debt recovery",
        ],
        "risks": [
            "Data subjects have right to object (Article 21)",
            "Must stop processing on objection unless compelling grounds exist",
            "Children's interests carry extra weight in balancing test",
            "Must be documented - ICO may ask to see the LIA",
        ],
    },
}

# ---------------------------------------------------------------------------
# Adequacy decisions for international transfers (Chapter V)
# ---------------------------------------------------------------------------
_ADEQUACY_COUNTRIES = [
    "Andorra", "Argentina", "Canada (PIPEDA)", "Faroe Islands", "Guernsey",
    "Isle of Man", "Israel", "Japan", "Jersey", "New Zealand",
    "Republic of Korea (South Korea)", "Switzerland", "United Kingdom",
    "United States (EU-US Data Privacy Framework participants only)",
    "Uruguay",
]

# ---------------------------------------------------------------------------
# ICO breach severity scoring
# ---------------------------------------------------------------------------
_BREACH_FACTORS = {
    "data_type": {
        "special_category": 4,
        "financial": 3,
        "personal_identifiers": 2,
        "contact_details": 1,
        "pseudonymised": 0.5,
    },
    "volume": {
        "over_10000": 4,
        "1001_to_10000": 3,
        "101_to_1000": 2,
        "11_to_100": 1,
        "1_to_10": 0.5,
    },
    "ease_of_identification": {
        "directly_identifiable": 3,
        "indirectly_identifiable": 2,
        "unlikely_identifiable": 1,
    },
    "severity_of_consequences": {
        "significant_harm": 4,
        "some_impact": 2,
        "minimal_impact": 1,
    },
}


# ===========================================================================
# MCP Tools
# ===========================================================================


@mcp.tool()
def classify_personal_data(
    fields: list[str],
    context: str = "") -> dict:
    """Classify data fields as personal, special category, or anonymous per GDPR.

    Analyses a list of data field names and classifies each according to
    GDPR Article 4 (personal data), Article 9 (special category data),
    and Article 10 (criminal offence data).

    Args:
        fields: List of data field names to classify (e.g. ["email", "health_data",
            "company_name", "date_of_birth"]).
        context: Optional context about how the data is used (affects classification
            of borderline cases like photographs or IP addresses).

    Returns:
        Classification of each field with GDPR article references and risk level.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded. Upgrade at https://dataprivacyof.ai/pricing"}

    if not fields:
        return {"error": "Provide at least one data field to classify."}

    results = []
    summary = {"personal": 0, "special": 0, "criminal": 0, "anonymous": 0, "not_personal": 0, "unknown": 0}

    for field in fields:
        field_lower = field.lower().strip().replace(" ", "_").replace("-", "_")

        # Direct match
        if field_lower in _DATA_CATEGORIES:
            info = _DATA_CATEGORIES[field_lower]
            category = info["category"]
        else:
            # Fuzzy match via keywords
            category = "unknown"
            info = None
            for key, cat_info in _DATA_CATEGORIES.items():
                if key in field_lower or field_lower in key:
                    info = cat_info
                    category = cat_info["category"]
                    break

            if not info:
                # Heuristic detection
                special_keywords = ["health", "medical", "ethnic", "racial", "religion", "politic", "genetic", "biometric", "sexual", "disability", "union"]
                criminal_keywords = ["criminal", "conviction", "offence", "arrest", "dbs"]
                personal_keywords = ["name", "email", "phone", "address", "birth", "age", "id", "number", "account"]

                if any(kw in field_lower for kw in special_keywords):
                    category = "special"
                    info = {"article": "9(1)", "description": f"Likely special category data based on field name '{field}'"}
                elif any(kw in field_lower for kw in criminal_keywords):
                    category = "criminal"
                    info = {"article": "10", "description": f"Likely criminal offence data based on field name '{field}'"}
                elif any(kw in field_lower for kw in personal_keywords):
                    category = "personal"
                    info = {"article": "4(1)", "description": f"Likely personal data based on field name '{field}'"}
                else:
                    info = {"article": "Unknown", "description": f"Could not classify '{field}'. Review manually."}

        summary[category] = summary.get(category, 0) + 1

        risk_level = {
            "special": "HIGH - requires Article 9 condition in addition to Article 6 lawful basis",
            "criminal": "HIGH - requires specific authority under domestic law (UK: DPA 2018 Schedule 1)",
            "personal": "STANDARD - requires Article 6 lawful basis",
            "anonymous": "LOW - not subject to GDPR if truly anonymised",
            "not_personal": "NONE - not personal data under GDPR",
            "unknown": "REVIEW REQUIRED - manual assessment needed",
        }.get(category, "REVIEW REQUIRED")

        results.append({
            "field": field,
            "category": category,
            "gdpr_article": info.get("article", "Unknown") if info else "Unknown",
            "description": info.get("description", "") if info else "",
            "risk_level": risk_level,
        })

    # Overall risk assessment
    if summary.get("special", 0) > 0 or summary.get("criminal", 0) > 0:
        overall_risk = "HIGH"
        risk_note = "Special category or criminal data detected. DPIA likely required (Article 35). Article 9 or Article 10 conditions must be met."
    elif summary.get("personal", 0) > 0:
        overall_risk = "STANDARD"
        risk_note = "Personal data present. Ensure valid Article 6 lawful basis for all processing activities."
    else:
        overall_risk = "LOW"
        risk_note = "No personal data detected. Verify that data cannot be combined with other data to identify individuals (Recital 26)."

    return {
        "classifications": results,
        "summary": summary,
        "overall_risk": overall_risk,
        "risk_note": risk_note,
        "guidance": {
            "special_category": "Article 9(2) conditions required: explicit consent, employment law, vital interests, legitimate activities of a body, manifestly public, legal claims, substantial public interest, health, public health, or archiving/research.",
            "pseudonymisation_note": "Pseudonymised data IS still personal data (Recital 26). Only fully anonymised data falls outside GDPR scope.",
        },
        "powered_by": "dataprivacyof.ai",
    }


@mcp.tool()
def assess_lawful_basis(
    processing_purpose: str,
    data_types: list[str],
    data_subjects: str = "customers",
    is_public_authority: bool = False,
    existing_relationship: bool = False,
    involves_children: bool = False) -> dict:
    """Determine appropriate lawful basis for processing personal data.

    Evaluates the six lawful bases under GDPR Article 6 and recommends
    the most appropriate basis for the described processing activity.

    Args:
        processing_purpose: Description of why data is being processed
            (e.g. "sending marketing emails", "processing payroll", "fraud detection").
        data_types: Types of data being processed (e.g. ["email", "name", "purchase_history"]).
        data_subjects: Who the data subjects are (e.g. "customers", "employees", "website_visitors").
        is_public_authority: Whether the controller is a public authority.
        existing_relationship: Whether there is an existing relationship with data subjects.
        involves_children: Whether processing involves children's data.

    Returns:
        Recommended lawful basis with justification, alternatives, and requirements.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    if not processing_purpose:
        return {"error": "Processing purpose is required."}

    purpose_lower = processing_purpose.lower()

    # Score each lawful basis for suitability
    scores = {}

    # Contract
    contract_keywords = ["order", "delivery", "payment", "subscription", "account", "service", "employment", "payroll", "quote", "booking"]
    if any(kw in purpose_lower for kw in contract_keywords) and existing_relationship:
        scores["contract"] = 5
    elif any(kw in purpose_lower for kw in contract_keywords):
        scores["contract"] = 3

    # Legal obligation
    legal_keywords = ["tax", "hmrc", "reporting", "aml", "anti-money", "health and safety", "statutory", "regulatory", "right to work"]
    if any(kw in purpose_lower for kw in legal_keywords):
        scores["legal_obligation"] = 5

    # Legitimate interests
    li_keywords = ["marketing", "fraud", "security", "analytics", "improve", "cctv", "direct mail", "debt", "research"]
    if any(kw in purpose_lower for kw in li_keywords) and not is_public_authority:
        scores["legitimate_interests"] = 4
        if involves_children:
            scores["legitimate_interests"] -= 2  # Children's interests weigh heavily
        # PECR: marketing to non-customers requires consent, not LI
        marketing_terms = ["marketing", "newsletter", "direct mail", "promotional"]
        if any(kw in purpose_lower for kw in marketing_terms) and not existing_relationship:
            scores["legitimate_interests"] = 2  # Demote LI — consent is correct basis per PECR Reg 22

    # Consent
    consent_keywords = ["newsletter", "marketing", "cookie", "tracking", "share with third", "profiling", "survey"]
    if any(kw in purpose_lower for kw in consent_keywords):
        scores["consent"] = 4
        # Boost consent for marketing without existing relationship (PECR requirement)
        marketing_terms = ["marketing", "newsletter", "direct mail", "promotional"]
        if any(kw in purpose_lower for kw in marketing_terms) and not existing_relationship:
            scores["consent"] = 5  # PECR Regulation 22: consent required for unsolicited marketing

    # Public task
    if is_public_authority:
        scores["public_task"] = 4

    # Vital interests (rarely appropriate)
    vital_keywords = ["emergency", "life-threatening", "safeguard"]
    if any(kw in purpose_lower for kw in vital_keywords):
        scores["vital_interests"] = 3

    # Default to consent if nothing else scores well
    if not scores:
        scores["consent"] = 3
        scores["legitimate_interests"] = 2

    # Sort by score
    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    recommended_key = ranked[0][0]
    recommended = _LAWFUL_BASES[recommended_key]

    alternatives = []
    for key, score in ranked[1:3]:
        alt = _LAWFUL_BASES[key]
        alternatives.append({
            "basis": alt["name"],
            "article": alt["article"],
            "suitability_note": f"Score: {score}/5 - may be appropriate depending on specific circumstances",
        })

    # Check for special category data
    has_special = False
    for dt in data_types:
        dt_lower = dt.lower().replace(" ", "_").replace("-", "_")
        cat = _DATA_CATEGORIES.get(dt_lower, {})
        if cat.get("category") in ("special", "criminal"):
            has_special = True
            break

    return {
        "processing_purpose": processing_purpose,
        "data_subjects": data_subjects,
        "recommended_lawful_basis": {
            "basis": recommended["name"],
            "article": recommended["article"],
            "description": recommended["description"],
            "requirements": recommended["requirements"],
            "when_appropriate": recommended["when_appropriate"],
            "risks": recommended["risks"],
        },
        "alternative_bases": alternatives,
        "special_category_warning": {
            "detected": has_special,
            "additional_requirement": (
                "Special category data detected. You MUST also identify an Article 9(2) condition "
                "in addition to your Article 6 lawful basis. Common conditions: explicit consent 9(2)(a), "
                "employment/social security law 9(2)(b), or substantial public interest 9(2)(g)."
            ) if has_special else None,
        },
        "children_warning": (
            "Processing involves children's data. Consider: (1) Age verification required, "
            "(2) Privacy notice must be child-friendly, (3) Consent requires parental authorisation "
            "for under-13s (UK) / under-16s (EU), (4) Legitimate interests balancing test weighs "
            "more heavily toward children's rights."
        ) if involves_children else None,
        "documentation_required": [
            "Record this lawful basis in your Record of Processing Activities (Article 30)",
            "Include the lawful basis in your privacy notice (Article 13(1)(c))",
            "If using legitimate interests: document and retain the Legitimate Interests Assessment",
            "If using consent: implement mechanism to record, manage, and withdraw consent",
        ],
        "powered_by": "dataprivacyof.ai",
    }


@mcp.tool()
def generate_dpia(
    project_name: str,
    processing_description: str,
    data_types: list[str],
    data_subjects: str,
    purpose: str,
    lawful_basis: str = "legitimate_interests",
    automated_decision_making: bool = False,
    large_scale: bool = False,
    systematic_monitoring: bool = False,
    new_technology: bool = False) -> dict:
    """Generate a Data Protection Impact Assessment template per GDPR Article 35.

    A DPIA is mandatory when processing is likely to result in a high risk
    to individuals' rights and freedoms. This generates a structured DPIA
    template with risk assessment and mitigation measures.

    Args:
        project_name: Name of the project/system being assessed.
        processing_description: Description of the processing operation.
        data_types: Types of personal data processed (e.g. ["email", "health_data", "location"]).
        data_subjects: Categories of data subjects (e.g. "employees", "patients", "children").
        purpose: Purpose of the processing.
        lawful_basis: Lawful basis under Article 6 (consent, contract, legal_obligation,
            vital_interests, public_task, legitimate_interests).
        automated_decision_making: Whether automated decision-making/profiling is involved.
        large_scale: Whether processing is on a large scale.
        systematic_monitoring: Whether systematic monitoring of public areas is involved.
        new_technology: Whether new/innovative technology is used.

    Returns:
        Complete DPIA template with risk assessment, necessity/proportionality analysis,
        and recommended mitigation measures.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    dpia_ref = f"DPIA-{uuid.uuid4().hex[:8].upper()}"
    now = datetime.now(timezone.utc)

    # Determine if DPIA is mandatory
    mandatory_triggers = []
    if automated_decision_making:
        mandatory_triggers.append("Automated decision-making with legal/significant effects (Article 35(3)(a))")
    if large_scale:
        has_special = any(
            _DATA_CATEGORIES.get(dt.lower().replace(" ", "_"), {}).get("category") in ("special", "criminal")
            for dt in data_types
        )
        if has_special:
            mandatory_triggers.append("Large-scale processing of special category data (Article 35(3)(b))")
    if systematic_monitoring:
        mandatory_triggers.append("Systematic monitoring of publicly accessible area on a large scale (Article 35(3)(c))")

    # ICO screening criteria
    screening_criteria_met = sum([
        automated_decision_making,
        large_scale,
        systematic_monitoring,
        new_technology,
        any(_DATA_CATEGORIES.get(dt.lower().replace(" ", "_"), {}).get("category") in ("special", "criminal") for dt in data_types),
        "children" in data_subjects.lower() or "vulnerable" in data_subjects.lower(),
    ])
    dpia_required = len(mandatory_triggers) > 0 or screening_criteria_met >= 2

    # Classify data types
    data_classification = []
    for dt in data_types:
        dt_key = dt.lower().replace(" ", "_").replace("-", "_")
        cat_info = _DATA_CATEGORIES.get(dt_key, {"category": "personal", "article": "4(1)", "description": dt})
        data_classification.append({"field": dt, "category": cat_info["category"], "article": cat_info["article"]})

    # Risk assessment
    risk_factors = []
    risk_score = 0

    if any(c["category"] == "special" for c in data_classification):
        risk_factors.append({"factor": "Special category data processed", "severity": "HIGH", "score": 4})
        risk_score += 4
    if large_scale:
        risk_factors.append({"factor": "Large-scale processing", "severity": "HIGH", "score": 3})
        risk_score += 3
    if automated_decision_making:
        risk_factors.append({"factor": "Automated decision-making", "severity": "HIGH", "score": 4})
        risk_score += 4
    if systematic_monitoring:
        risk_factors.append({"factor": "Systematic monitoring", "severity": "HIGH", "score": 3})
        risk_score += 3
    if new_technology:
        risk_factors.append({"factor": "New/innovative technology", "severity": "MEDIUM", "score": 2})
        risk_score += 2
    if "children" in data_subjects.lower():
        risk_factors.append({"factor": "Vulnerable data subjects (children)", "severity": "HIGH", "score": 4})
        risk_score += 4

    if risk_score >= 8:
        overall_risk = "HIGH"
    elif risk_score >= 4:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # Mitigation measures
    mitigations = [
        {"measure": "Data minimisation - collect only data strictly necessary for the purpose", "article": "5(1)(c)", "priority": "ESSENTIAL"},
        {"measure": "Encryption at rest and in transit (AES-256 / TLS 1.3)", "article": "32(1)(a)", "priority": "ESSENTIAL"},
        {"measure": "Access controls - role-based access, principle of least privilege", "article": "32(1)(b)", "priority": "ESSENTIAL"},
        {"measure": "Regular data protection training for all staff with access", "article": "39(1)(b)", "priority": "HIGH"},
        {"measure": "Data retention policy - delete data when no longer needed", "article": "5(1)(e)", "priority": "ESSENTIAL"},
        {"measure": "Incident response plan with 72-hour breach notification capability", "article": "33", "priority": "ESSENTIAL"},
        {"measure": "Privacy by design and by default implemented in system architecture", "article": "25", "priority": "HIGH"},
        {"measure": "Regular penetration testing and vulnerability scanning", "article": "32(1)(d)", "priority": "HIGH"},
    ]

    if automated_decision_making:
        mitigations.append({"measure": "Human oversight mechanism for automated decisions", "article": "22(3)", "priority": "ESSENTIAL"})
        mitigations.append({"measure": "Right to contest automated decisions and obtain human review", "article": "22(3)", "priority": "ESSENTIAL"})
    if large_scale:
        mitigations.append({"measure": "Pseudonymisation of data where possible", "article": "32(1)(a)", "priority": "HIGH"})
    if any(c["category"] == "special" for c in data_classification):
        mitigations.append({"measure": "Enhanced security measures for special category data", "article": "9, 32", "priority": "ESSENTIAL"})

    lawful_basis_info = _LAWFUL_BASES.get(lawful_basis, _LAWFUL_BASES["legitimate_interests"])

    return {
        "dpia": {
            "reference": dpia_ref,
            "date": now.strftime("%Y-%m-%d"),
            "project_name": project_name,
            "assessor": "To be completed",
            "dpo_consulted": "To be completed",
            "status": "DRAFT",
        },
        "dpia_required": dpia_required,
        "mandatory_triggers": mandatory_triggers,
        "screening_criteria_met": screening_criteria_met,
        "section_1_processing_description": {
            "description": processing_description,
            "purpose": purpose,
            "data_types": data_classification,
            "data_subjects": data_subjects,
            "lawful_basis": {"basis": lawful_basis_info["name"], "article": lawful_basis_info["article"]},
            "retention_period": "To be specified",
            "recipients": "To be specified",
        },
        "section_2_necessity_and_proportionality": {
            "questions": [
                {"q": "Is the processing necessary for the stated purpose?", "guidance": "Could the purpose be achieved with less data or less intrusive means?"},
                {"q": "Is the purpose legitimate and clearly defined?", "guidance": "Article 5(1)(b) - purpose limitation principle"},
                {"q": "Is the data adequate, relevant, and limited to what is necessary?", "guidance": "Article 5(1)(c) - data minimisation principle"},
                {"q": "How will data quality and accuracy be ensured?", "guidance": "Article 5(1)(d) - accuracy principle"},
                {"q": "How will data subjects exercise their rights?", "guidance": "Articles 15-22 - data subject rights"},
            ],
        },
        "section_3_risk_assessment": {
            "risk_factors": risk_factors,
            "overall_risk_score": risk_score,
            "overall_risk_level": overall_risk,
            "risks_to_individuals": [
                "Unauthorised access to personal data",
                "Accidental loss or destruction of data",
                "Excessive or inaccurate data processing",
                "Inability to exercise data subject rights",
                "Discrimination or unfair treatment based on processing",
            ],
        },
        "section_4_mitigation_measures": mitigations,
        "section_5_sign_off": {
            "dpo_advice": "DPO to review and provide written advice",
            "controller_decision": "Controller to accept, modify, or reject DPO advice",
            "review_date": "DPIA must be reviewed if processing changes or at least annually",
        },
        "article_36_prior_consultation": (
            "If high risks cannot be sufficiently mitigated, you MUST consult the ICO "
            "(UK) or relevant Supervisory Authority (EU) BEFORE processing begins (Article 36)."
        ) if overall_risk == "HIGH" else None,
        "powered_by": "dataprivacyof.ai",
    }


@mcp.tool()
def check_data_transfer(
    destination_country: str,
    transfer_mechanism: Optional[str] = None,
    data_types: Optional[list[str]] = None,
    recipient_type: str = "processor") -> dict:
    """Assess legality of international personal data transfers under GDPR Chapter V.

    Evaluates whether a transfer to a non-UK/EU country is lawful by checking
    adequacy decisions, Standard Contractual Clauses, Binding Corporate Rules,
    and derogations.

    Args:
        destination_country: Country receiving the data (e.g. "United States", "India", "Australia").
        transfer_mechanism: Proposed transfer mechanism: "adequacy", "sccs", "bcrs",
            "derogation_consent", "derogation_contract", "derogation_public_interest".
            If not provided, the tool will recommend appropriate mechanisms.
        data_types: Optional list of data types being transferred.
        recipient_type: Relationship with recipient: "processor" (acting on your instructions),
            "controller" (determines own purposes), "joint_controller".

    Returns:
        Transfer assessment with required safeguards and documentation.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    country = destination_country.strip()

    # Check adequacy
    has_adequacy = any(
        country.lower() in ac.lower() or ac.lower() in country.lower()
        for ac in _ADEQUACY_COUNTRIES
    )

    # US special case
    us_dpf = False
    if "united states" in country.lower() or "usa" in country.lower() or country.lower() == "us":
        us_dpf = True
        has_adequacy = False  # Only adequate for DPF participants

    # Determine recommended mechanism
    if has_adequacy:
        recommended_mechanism = "adequacy"
    elif us_dpf:
        recommended_mechanism = "sccs_or_dpf"
    else:
        recommended_mechanism = transfer_mechanism or "sccs"

    # Build assessment
    mechanisms = {
        "adequacy": {
            "name": "Adequacy Decision",
            "article": "45",
            "description": f"{country} has been recognised as providing an adequate level of data protection.",
            "requirements": [
                "No additional safeguards required for the transfer itself",
                "Must still comply with all other GDPR principles",
                "Adequacy decisions can be revoked - monitor for changes",
            ],
            "valid": has_adequacy,
        },
        "sccs": {
            "name": "Standard Contractual Clauses (SCCs)",
            "article": "46(2)(c)",
            "description": "EU Commission-approved contractual clauses providing appropriate safeguards.",
            "requirements": [
                "Use the 2021 SCCs (Commission Implementing Decision 2021/914) - old SCCs no longer valid",
                "Conduct a Transfer Impact Assessment (TIA) for the destination country",
                "Implement supplementary measures if TIA identifies risks (Schrems II)",
                "Select correct module: C2C (controller-to-controller), C2P (controller-to-processor), P2P, P2C",
                "SCCs cannot be modified (but additional clauses can be added if not contradictory)",
                "UK: use International Data Transfer Agreement (IDTA) or EU SCCs with UK Addendum",
            ],
            "valid": True,
        },
        "bcrs": {
            "name": "Binding Corporate Rules",
            "article": "46(2)(b), 47",
            "description": "Internal rules adopted by a multinational group for intra-group transfers.",
            "requirements": [
                "Must be approved by the competent Supervisory Authority",
                "Approval process takes 12-18 months minimum",
                "Must include all GDPR principles (Article 47(2))",
                "Legally binding on all group members",
                "Data subjects must be third-party beneficiaries",
                "Suitable only for large multinational organisations",
            ],
            "valid": True,
        },
        "sccs_or_dpf": {
            "name": "SCCs or EU-US Data Privacy Framework",
            "article": "45 (DPF) or 46(2)(c) (SCCs)",
            "description": "For US transfers: check if recipient participates in the EU-US Data Privacy Framework. If not, use SCCs.",
            "requirements": [
                "DPF: Verify recipient is on the DPF list (https://www.dataprivacyframework.gov/list)",
                "DPF: Adequacy decision applies only to DPF-certified organisations",
                "SCCs: Required if recipient is NOT DPF-certified",
                "SCCs: Must conduct Transfer Impact Assessment considering US surveillance laws (FISA 702, EO 12333)",
                "Consider supplementary measures: encryption, pseudonymisation, split processing",
            ],
            "valid": True,
        },
    }

    selected = mechanisms.get(recommended_mechanism, mechanisms["sccs"])

    # Derogations (Article 49) - last resort
    derogations = [
        {"derogation": "Explicit consent", "article": "49(1)(a)", "note": "Data subject informed of risks; consent can be withdrawn"},
        {"derogation": "Necessary for contract performance", "article": "49(1)(b)", "note": "Contract between data subject and controller"},
        {"derogation": "Important public interest", "article": "49(1)(d)", "note": "Must be recognised in UK/EU law"},
        {"derogation": "Legal claims", "article": "49(1)(e)", "note": "Necessary for establishment, exercise, or defence of legal claims"},
        {"derogation": "Vital interests", "article": "49(1)(f)", "note": "Only where data subject is physically/legally incapable of giving consent"},
    ]

    # Classify transferred data
    data_risk = "STANDARD"
    if data_types:
        for dt in data_types:
            dt_key = dt.lower().replace(" ", "_").replace("-", "_")
            cat = _DATA_CATEGORIES.get(dt_key, {})
            if cat.get("category") in ("special", "criminal"):
                data_risk = "HIGH"
                break

    return {
        "destination_country": country,
        "adequacy_decision_exists": has_adequacy,
        "recommended_mechanism": selected,
        "recipient_type": recipient_type,
        "data_risk_level": data_risk,
        "transfer_impact_assessment": {
            "required": not has_adequacy,
            "description": (
                "A Transfer Impact Assessment (TIA) evaluates the laws and practices "
                "of the destination country to determine if the transfer mechanism provides "
                "essentially equivalent protection. Required post-Schrems II (C-311/18)."
            ),
            "factors_to_assess": [
                "Rule of law and respect for human rights",
                "Government access to personal data (surveillance laws)",
                "Effective data protection legislation and enforcement",
                "Access to judicial or administrative redress",
                "International commitments on data protection",
            ],
        },
        "derogations_article_49": {
            "note": "Derogations are a LAST RESORT. They cannot be used for systematic/regular transfers.",
            "available_derogations": derogations,
        },
        "documentation_required": [
            f"Record the transfer in your Article 30 Record of Processing Activities",
            f"Document the transfer mechanism and any TIA conducted",
            f"For SCCs: retain signed copies and review annually",
            f"Update privacy notice to inform data subjects of international transfers (Article 13(1)(f))",
        ],
        "powered_by": "dataprivacyof.ai",
    }


@mcp.tool()
def calculate_breach_severity(
    data_types_affected: list[str],
    number_of_individuals: int,
    breach_type: str = "confidentiality",
    data_encrypted: bool = False,
    data_backed_up: bool = True,
    containment_time_hours: float = 24,
    likely_consequences: str = "some_impact") -> dict:
    """Score a data breach severity and determine ICO notification requirements.

    Assesses whether a breach must be reported to the ICO (within 72 hours
    per Article 33) and/or to affected individuals (Article 34). Uses a
    risk-based scoring approach aligned with EDPB and ICO guidance.

    Args:
        data_types_affected: Types of data breached (e.g. ["email", "health_data", "credit_card"]).
        number_of_individuals: Number of data subjects affected.
        breach_type: Type of breach: "confidentiality" (unauthorised access/disclosure),
            "integrity" (unauthorised alteration), "availability" (loss of access/destruction).
        data_encrypted: Whether the breached data was encrypted.
        data_backed_up: Whether data can be restored from backups (for availability breaches).
        containment_time_hours: Time to contain the breach in hours.
        likely_consequences: Impact on individuals: "significant_harm" (identity theft,
            financial loss, discrimination), "some_impact" (inconvenience, distress),
            "minimal_impact" (unlikely to affect individuals).

    Returns:
        Breach severity score, ICO notification requirement, and response checklist.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    # Score data sensitivity
    max_data_score = 0
    data_categories_found = []
    for dt in data_types_affected:
        dt_key = dt.lower().replace(" ", "_").replace("-", "_")
        cat = _DATA_CATEGORIES.get(dt_key, {"category": "personal"})
        data_categories_found.append({"field": dt, "category": cat.get("category", "personal")})
        cat_name = cat.get("category", "personal")
        scores = {"special": 4, "criminal": 4, "personal": 2, "anonymous": 0, "not_personal": 0}
        max_data_score = max(max_data_score, scores.get(cat_name, 2))

    # Score volume
    if number_of_individuals > 10000:
        volume_score = 4
    elif number_of_individuals > 1000:
        volume_score = 3
    elif number_of_individuals > 100:
        volume_score = 2
    elif number_of_individuals > 10:
        volume_score = 1
    else:
        volume_score = 0.5

    # Score consequences
    consequence_scores = {"significant_harm": 4, "some_impact": 2, "minimal_impact": 1}
    consequence_score = consequence_scores.get(likely_consequences, 2)

    # Mitigating factors
    mitigation = 0
    if data_encrypted:
        mitigation -= 3  # Encryption significantly reduces risk
    if data_backed_up and breach_type == "availability":
        mitigation -= 2
    if containment_time_hours <= 1:
        mitigation -= 1
    elif containment_time_hours > 72:
        mitigation += 1

    # Total score (0-16 scale)
    total_score = max(0, max_data_score + volume_score + consequence_score + mitigation)

    # Determine notification requirements
    if total_score >= 6 or (max_data_score >= 4 and number_of_individuals > 0):
        notify_ico = True
        notify_individuals = total_score >= 8
        risk_level = "HIGH"
    elif total_score >= 3:
        notify_ico = True
        notify_individuals = False
        risk_level = "MEDIUM"
    elif data_encrypted and containment_time_hours <= 24:
        notify_ico = False
        notify_individuals = False
        risk_level = "LOW"
    else:
        notify_ico = total_score >= 2
        notify_individuals = False
        risk_level = "LOW"

    # 72-hour deadline
    deadline_note = None
    if notify_ico:
        deadline_note = (
            "You MUST notify the ICO within 72 hours of becoming aware of the breach (Article 33). "
            "If you cannot provide full details within 72 hours, provide what you can and supplement later. "
            "ICO breach reporting: https://ico.org.uk/make-a-complaint/data-protection-complaints/data-protection-complaints/"
        )

    return {
        "breach_assessment": {
            "data_types_affected": data_categories_found,
            "number_of_individuals": number_of_individuals,
            "breach_type": breach_type,
            "data_encrypted": data_encrypted,
        },
        "severity_scoring": {
            "data_sensitivity_score": max_data_score,
            "volume_score": volume_score,
            "consequence_score": consequence_score,
            "mitigation_adjustment": mitigation,
            "total_score": round(total_score, 1),
            "risk_level": risk_level,
        },
        "notification_requirements": {
            "notify_ico": notify_ico,
            "ico_deadline": "72 hours from awareness" if notify_ico else "Not required",
            "notify_individuals": notify_individuals,
            "individual_notification_article": "Article 34" if notify_individuals else None,
            "deadline_note": deadline_note,
        },
        "response_checklist": [
            {"step": "1. CONTAIN the breach immediately", "done": False, "priority": "CRITICAL"},
            {"step": "2. ASSESS the risk to individuals", "done": False, "priority": "CRITICAL"},
            {"step": "3. NOTIFY ICO within 72 hours (if required)", "done": False, "priority": "CRITICAL" if notify_ico else "N/A"},
            {"step": "4. NOTIFY affected individuals without undue delay (if required)", "done": False, "priority": "HIGH" if notify_individuals else "N/A"},
            {"step": "5. DOCUMENT the breach (regardless of whether reported)", "done": False, "priority": "ESSENTIAL"},
            {"step": "6. REVIEW and implement measures to prevent recurrence", "done": False, "priority": "HIGH"},
        ],
        "documentation_required": {
            "article": "Article 33(5)",
            "must_record": [
                "Facts relating to the breach",
                "Its effects",
                "Remedial action taken",
                "This must be recorded EVEN IF the breach is not reported to the ICO",
            ],
        },
        "ico_contact": {
            "phone": "0303 123 1113 (live reporting line)",
            "online": "https://ico.org.uk/make-a-complaint/data-protection-complaints/",
            "hours": "Monday to Friday, 9am to 5pm",
        },
        "powered_by": "dataprivacyof.ai",
    }


@mcp.tool()
def generate_privacy_notice(
    controller_name: str,
    controller_contact: str,
    dpo_contact: Optional[str] = None,
    purposes: list[str] = None,
    lawful_bases: Optional[list[str]] = None,
    data_categories: Optional[list[str]] = None,
    recipients: Optional[list[str]] = None,
    international_transfers: bool = False,
    retention_period: str = "",
    automated_decisions: bool = False,
    website_url: str = "") -> dict:
    """Generate an Article 13/14 compliant privacy notice.

    Creates a GDPR-compliant privacy notice covering all mandatory information
    required by Articles 13 (data collected from the individual) and 14
    (data obtained from other sources).

    Args:
        controller_name: Name of the data controller (organisation).
        controller_contact: Contact details for the controller.
        dpo_contact: Data Protection Officer contact (required for public authorities
            and organisations processing special category data at scale).
        purposes: List of processing purposes (e.g. ["provide services", "send marketing", "fraud prevention"]).
        lawful_bases: Lawful bases for each purpose (e.g. ["contract", "consent", "legitimate_interests"]).
        data_categories: Types of personal data collected (e.g. ["name", "email", "payment_details"]).
        recipients: Categories of recipients data is shared with (e.g. ["payment processors", "delivery partners"]).
        international_transfers: Whether data is transferred outside UK/EEA.
        retention_period: How long data is retained (e.g. "6 years after last transaction").
        automated_decisions: Whether automated decision-making/profiling is used.
        website_url: Website URL for the notice.

    Returns:
        Complete privacy notice text with all Article 13/14 mandatory sections.
    """
    if not _check_rate_limit():
        return {"error": "Rate limit exceeded."}

    if not controller_name or not controller_contact:
        return {"error": "Controller name and contact details are required."}

    purposes = purposes or ["provide our services"]
    lawful_bases = lawful_bases or ["contract"]
    data_categories = data_categories or ["name", "email", "phone"]
    recipients = recipients or []

    notice_ref = f"PN-{uuid.uuid4().hex[:6].upper()}"
    generated_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Map lawful bases to readable text
    basis_text = []
    for i, purpose in enumerate(purposes):
        basis = lawful_bases[i] if i < len(lawful_bases) else lawful_bases[-1]
        basis_info = _LAWFUL_BASES.get(basis, _LAWFUL_BASES["consent"])
        basis_text.append({
            "purpose": purpose,
            "lawful_basis": basis_info["name"],
            "article": basis_info["article"],
        })

    # Build data subject rights section
    rights = [
        {"right": "Right of access", "article": "15", "description": "You can request a copy of the personal data we hold about you (Subject Access Request). We must respond within one month."},
        {"right": "Right to rectification", "article": "16", "description": "You can ask us to correct inaccurate personal data or complete incomplete data."},
        {"right": "Right to erasure", "article": "17", "description": "You can ask us to delete your personal data in certain circumstances (also known as the 'right to be forgotten')."},
        {"right": "Right to restrict processing", "article": "18", "description": "You can ask us to limit how we use your data in certain circumstances."},
        {"right": "Right to data portability", "article": "20", "description": "You can ask us to transfer your data to you or another organisation in a machine-readable format."},
        {"right": "Right to object", "article": "21", "description": "You can object to processing based on legitimate interests or for direct marketing purposes. We must stop unless we have compelling grounds."},
    ]

    if automated_decisions:
        rights.append({
            "right": "Rights related to automated decision-making",
            "article": "22",
            "description": "You have the right not to be subject to a decision based solely on automated processing that produces legal or similarly significant effects. You can request human intervention, express your point of view, and contest the decision.",
        })

    if "consent" in (lawful_bases or []):
        rights.append({
            "right": "Right to withdraw consent",
            "article": "7(3)",
            "description": "Where we process your data based on consent, you can withdraw consent at any time. This will not affect the lawfulness of processing before withdrawal.",
        })

    return {
        "privacy_notice": {
            "reference": notice_ref,
            "generated_date": generated_date,
            "last_updated": generated_date,
            "website": website_url,
        },
        "section_1_identity_and_contact": {
            "article": "13(1)(a)",
            "controller_name": controller_name,
            "controller_contact": controller_contact,
            "dpo_contact": dpo_contact or "Not appointed (review whether DPO is required under Article 37)",
        },
        "section_2_purposes_and_lawful_basis": {
            "article": "13(1)(c), 13(1)(d)",
            "processing_activities": basis_text,
        },
        "section_3_categories_of_data": {
            "article": "14(1)(d) (required when data not collected from individual)",
            "data_collected": data_categories,
        },
        "section_4_recipients": {
            "article": "13(1)(e)",
            "recipients": recipients if recipients else ["We do not share your personal data with third parties except as described in this notice."],
            "note": "List all categories of recipients, including processors acting on your behalf.",
        },
        "section_5_international_transfers": {
            "article": "13(1)(f)",
            "transfers_outside_uk_eea": international_transfers,
            "safeguards": (
                "Where we transfer your personal data outside the UK/EEA, we ensure appropriate "
                "safeguards are in place, such as Standard Contractual Clauses approved by the "
                "European Commission, or transfers to countries with an adequacy decision."
            ) if international_transfers else "We do not transfer your personal data outside the UK/EEA.",
        },
        "section_6_retention": {
            "article": "13(2)(a)",
            "retention_period": retention_period or "We retain your personal data only for as long as necessary for the purposes set out in this notice, and in accordance with our data retention policy.",
        },
        "section_7_your_rights": {
            "article": "13(2)(b-d)",
            "rights": rights,
            "how_to_exercise": f"To exercise any of these rights, contact us at: {controller_contact}",
        },
        "section_8_automated_decisions": {
            "article": "13(2)(f)",
            "automated_decision_making": automated_decisions,
            "description": (
                "We use automated decision-making in our processing. You have the right to "
                "request human intervention, express your point of view, and contest decisions."
            ) if automated_decisions else "We do not use automated decision-making that produces legal or similarly significant effects on you.",
        },
        "section_9_right_to_complain": {
            "article": "13(2)(d)",
            "text": (
                "You have the right to lodge a complaint with a supervisory authority. "
                "In the UK, this is the Information Commissioner's Office (ICO)."
            ),
            "ico_details": {
                "website": "https://ico.org.uk/make-a-complaint/",
                "phone": "0303 123 1113",
                "address": "Information Commissioner's Office, Wycliffe House, Water Lane, Wilmslow, Cheshire, SK9 5AF",
            },
        },
        "section_10_updates": {
            "text": "We may update this privacy notice from time to time. We will notify you of any significant changes.",
        },
        "compliance_checklist": {
            "article_13_mandatory_info": [
                "Identity and contact details of controller - INCLUDED",
                "DPO contact details - " + ("INCLUDED" if dpo_contact else "REVIEW NEEDED"),
                "Purposes and lawful basis - INCLUDED",
                "Legitimate interests (if applicable) - REVIEW",
                "Recipients/categories of recipients - INCLUDED",
                "International transfer details - INCLUDED",
                "Retention period - " + ("INCLUDED" if retention_period else "SPECIFY NEEDED"),
                "Data subject rights - INCLUDED",
                "Right to withdraw consent - " + ("INCLUDED" if "consent" in lawful_bases else "N/A"),
                "Right to complain to ICO - INCLUDED",
                "Automated decision-making info - INCLUDED",
            ],
        },
        "powered_by": "dataprivacyof.ai",
    }


if __name__ == "__main__":
    mcp.run()
