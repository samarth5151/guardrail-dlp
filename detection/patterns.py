"""
DLP Gateway — Detection Patterns
All regex, keyword, and entropy config in one place.
"""
import re

# ── Layer 1: Credentials & API Keys ──────────────────────────────────────────
CREDENTIAL_PATTERNS = [
    (r"\bAKIA[0-9A-Z]{16}\b",                                           "AWS Access Key",           0.99),
    (r"\bASIA[0-9A-Z]{16}\b",                                           "AWS Session Key",          0.97),
    (r"(?i)aws[_\s-]*secret[_\s-]*(?:access[_\s-]*)?key\s*[=:]\s*\S+", "AWS Secret Key",           0.99),
    (r"\bsk-[A-Za-z0-9]{32,}\b",                                        "OpenAI API Key",           0.97),
    (r"\bsk-ant-[A-Za-z0-9\-]{32,}\b",                                  "Anthropic Key",            0.97),
    (r"\bhf_[A-Za-z0-9]{30,}\b",                                        "HuggingFace Token",        0.90),
    (r"\bghp_[A-Za-z0-9]{36}\b",                                        "GitHub PAT",               0.95),
    (r"\bgho_[A-Za-z0-9]{36}\b",                                        "GitHub OAuth Token",       0.94),
    (r"\bglpat-[A-Za-z0-9\-_]{20,}\b",                                  "GitLab Token",             0.92),
    (r"\bAIza[0-9A-Za-z\-_]{35}\b",                                     "Google API Key",           0.93),
    (r"\bsk_live_[A-Za-z0-9]{24,}\b",                                   "Stripe Secret Key",        0.99),
    (r"\brk_live_[A-Za-z0-9]{24,}\b",                                   "Stripe Restricted Key",    0.97),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+", "JWT Token",                0.88),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",         "Private Key",              1.00),
    (r"-----BEGIN CERTIFICATE-----",                                     "Certificate",              0.75),
    # Password with explicit keyword — match any non-space value >= 4 chars
    (r"(?i)(?:password|passwd|pwd|secret|api_key|apikey)\s*[=:]\s*\S{4,}",
                                                                         "Hardcoded Password",       0.90),
    # Hex-encoded secrets (long hexadecimal strings context)
    (r"(?i)(?:key|secret|token|hash)\s*(?:is|:|=)\s*[0-9A-Fa-f]{32,}",
                                                                         "Hex Encoded Secret",       0.85),
    # Complex password heuristic: 8+ chars with upper+lower+digit+special
    (r"(?:^|[\s\"'(])(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*\-_+=])[A-Za-z\d!@#$%^&*\-_+=]{8,24}(?:$|[\s)\"',.])",
                                                                         "Complex Password",         0.90),
    (r"\bAC[a-z0-9]{32}\b",                                             "Twilio SID",               0.88),
    (r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b",               "SendGrid Key",             0.95),
    (r"\bxoxb-[0-9A-Za-z\-]{50,}\b",                                   "Slack Bot Token",          0.95),
]

# ── Layer 2: Financial Data ───────────────────────────────────────────────────
CARD_REGEX = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
    r"3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|"
    r"6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
)

FINANCIAL_PATTERNS = [
    # IBAN — allows optional spaces between groups, more robust check
    (r"\b[A-Z]{2}[0-9]{2}(?:\s?[A-Z0-9]{4}){4,9}\b",                  "IBAN",                     0.95),
    # UK Sort Code  xx-xx-xx
    (r"\b\d{2}-\d{2}-\d{2}\b",                                          "UK Sort Code",             0.65),
    # Bank account number (8-12 digits, with or without keyword)
    (r"(?i)account\s*(?:number|no|#)?\s*[=:]?\s*(\d{8,12})\b",         "Bank Account Number",      0.88),
    # SWIFT/BIC — only when 8 or 11 chars (avoid matching random caps)
    (r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b(?=\s|$)",      "SWIFT/BIC Code",           0.70),
    # CVV — keyword + 'is/was' OR '=' + 3-4 digit code
    (r"(?i)(?:cvv|cvc|cvv2)\s*(?:is|was|[=:])\s*\d{3,4}\b",             "CVV/CVC Code",             0.96),
    # PIN number
    (r"(?i)(?:pin|pin\s*code|pin\s*number)\s*[=:]\s*\d{4,6}",          "PIN Number",               0.96),
    # ABA Routing number
    (r"(?i)routing\s*(?:number|no)?\s*[=:]?\s*([0-9]{9})\b",           "ABA Routing Number",       0.88),
    # India IFSC
    (r"\b[A-Z]{4}0[A-Z0-9]{6}\b",                                       "IFSC Code",                0.88),
    # Transaction data
    (r"(?i)(?:transaction\s*(?:id|ref|amount|date)|txn\s*id)\s*[=:]\s*\S+",
                                                                          "Transaction Data",         0.80),
]

# ── Layer 3: PII Patterns ─────────────────────────────────────────────────────
PII_PATTERNS = [
    # Global
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",           "Email Address",            0.80),
    (r"\b(?:\+?44\s?)?(?:0\s?)?(?:\d[\s-]?){9,11}\d\b",               "UK Phone Number",          0.72),
    (r"\b[A-Z]{2}[0-9]{6}[A-Z]\b",                                      "UK NI Number",             0.90),
    # SSN — dashed format xxx-xx-xxxx
    (r"\b\d{3}-\d{2}-\d{4}\b",                                           "US SSN",                   0.95),
    (r"(?i)ssn\s*[=:#]?\s*\d{3}-?\d{2}-?\d{4}",                         "US SSN",                   0.97),
    (r"(?i)date\s+of\s+birth\s*[=:]\s*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}", "Date of Birth",            0.82),
    # Salary — keyword + optional separator + 4+ digit number
    (r"(?i)salary\s*[=:]?\s*[\d,]{4,}\b",                               "Salary Figure",            0.88),
    (r"(?i)(?:compensation|ctc|annual\s+pay)\s*[=:]?\s*[\d,]{4,}\b",    "Salary Figure",            0.82),
    # Passport — must have keyword prefix
    (r"(?i)passport\s*(?:number|no|#|num|id)?[:\s]\s*[A-Z]{1,2}\d{6,9}\b",
                                                                          "Passport Number",          0.92),
    # India-specific
    (r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",                   "Aadhaar Number",           0.97),
    (r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",                                   "PAN Number",               0.95),
]

PII_NER_LABELS = [
    "person name", "email address", "phone number", "national ID",
    "passport number", "date of birth", "home address",
    "social security number", "salary figure",
    "national insurance number", "bank account number",
    "aadhaar number", "PAN number",
]

# ── Layer 4: Confidential Watermarks ─────────────────────────────────────────
CONFIDENTIAL_PATTERNS = [
    (r"(?i)\b(STRICTLY\s+CONFIDENTIAL|BARCLAYS\s+INTERNAL|BARCLAYS\s+CONFIDENTIAL)\b",
     "Barclays Confidential",       0.98),
    (r"(?i)\b(CONFIDENTIAL|INTERNAL\s+USE\s+ONLY|FOR\s+INTERNAL\s+USE)\b",
     "Confidential Document",       0.90),
    (r"(?i)\b(NOT\s+FOR\s+(?:EXTERNAL|PUBLIC)\s+(?:DISTRIBUTION|SHARING|RELEASE))\b",
     "Restricted Distribution",     0.93),
    (r"(?i)\b(RESTRICTED|PROPRIETARY|TRADE\s+SECRET)\b",
     "Proprietary Information",     0.85),
    (r"(?i)\b(PRIVILEGED\s+AND\s+CONFIDENTIAL|ATTORNEY[-\u2013]CLIENT\s+PRIVILEGE)\b",
     "Legal Privilege",             0.95),
    # Internal URLs — require the barclays subdomain to avoid matching 'barclays' in text
    (r"(?i)(?:https?://)[\w\-]+\.barclays(?:corporate|internal|intranet)?\.(?:com|net|local|int)\b",
     "Internal Barclays URL",       0.87),
    (r"(?i)(?:https?://)?intranet\.[\w\-]+\.(?:com|net|local|int)\b",
     "Intranet URL",                0.80),
    (r"(?i)\b(merger|acquisition|M&A|takeover|buyout)\s+(?:talks?|plans?|agreement|terms)\b",
     "M&A Sensitive Info",          0.92),
    # Financial results / Earnings context (WARN)
    (r"(?i)\b(quarterly\s+(?:results?|earnings?|financials?|numbers?)|financial\s+results?)\b",
     "Financial Results",           0.45),
]

# ── Layer 5: Employee & HR Data ───────────────────────────────────────────────
EMPLOYEE_PATTERNS = [
    (r"(?i)\b(employee\s+(?:id|number|data|records?|salary|compensation))\b",
     "Employee Data",               0.60), # Lowered from 0.70
    (r"(?i)\b(hr\s+(?:record|data|report|file|database))\b",
     "HR Records",                  0.68),
    (r"(?i)\b(annual\s+(?:review|appraisal|performance\s+rating))\b",
     "Performance Review",          0.65),
    (r"(?i)\b(payroll|pay\s*slip|pay\s*stub|pay\s*cheque)\b",
     "Payroll Data",                0.88),
    (r"(?i)\b(headcount|redundancy|layoff|termination\s+letter)\b",
     "HR Decision Data",            0.72),
    (r"(?i)\b(internal\s+(?:memo|communication|email|message))\b",
     "Internal Communication",      0.60),
    # HR decisions — explicit termination / dismissal keywords
    (r"(?i)\b(?:recommend\s+)?(?:termination|dismissal|firing|laid\s+off|let\s+go)\b",
     "HR Decision Data",            0.75),
]

# ── Layer 6: Business Strategy Data ──────────────────────────────────────────
STRATEGY_PATTERNS = [
    (r"(?i)\b(investment\s+(?:thesis|strategy))\b",
     "Investment Strategy",         0.72),
    (r"(?i)\b(board\s+(?:decision|meeting\s+minutes|resolution))\b",
     "Board Decision",              0.76),
    (r"(?i)\b(strategic\s+(?:plan|initiative|roadmap|objective))\b",
     "Strategic Plan",              0.55),
    (r"(?i)\b(product\s+(?:roadmap|strategy|launch\s+plan))\b",
     "Product Roadmap",             0.30),  # Well below WARN threshold
    (r"(?i)\b(competitive\s+(?:analysis|intelligence|strategy))\b",
     "Competitive Intelligence",    0.65),
    (r"(?i)\b(revenue\s+(?:forecast|target|projection))\b",
     "Revenue Forecast",            0.72),
    (r"(?i)\b(budget\s+(?:plan|allocation|forecast|2024|2025|2026))\b",
     "Budget Data",                 0.65),
]

# ── Entropy Config ────────────────────────────────────────────────────────────
ENTROPY_MIN_LENGTH     = 20     # min token length to check entropy
ENTROPY_THRESHOLD      = 4.5    # Shannon bits; above = likely a secret
ENTROPY_SEVERITY       = 0.82

# ── Fuzzy Match Config ────────────────────────────────────────────────────────
FUZZY_KEYWORDS = [
    "barclays internal", "strictly confidential", "do not distribute",
    "confidential document", "internal use only", "proprietary algorithm",
    "trade secret", "not for external", "m&a discussion",
    "merger talks", "acquisition plan",
]
FUZZY_THRESHOLD   = 85   # RapidFuzz ratio
FUZZY_SEVERITY    = 0.80

# ── Invisible / Taint Chars ───────────────────────────────────────────────────
INVISIBLE_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad", "\u2060"}
