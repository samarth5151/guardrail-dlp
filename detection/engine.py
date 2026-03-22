"""
DLP Gateway — Detection Engine
Async, parallel multi-layer scanner.
"""
from __future__ import annotations

import re
import math
import base64
import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict

from detection.patterns import (
    CREDENTIAL_PATTERNS, CARD_REGEX, FINANCIAL_PATTERNS,
    PII_PATTERNS, PII_NER_LABELS, CONFIDENTIAL_PATTERNS,
    EMPLOYEE_PATTERNS, STRATEGY_PATTERNS,
    ENTROPY_MIN_LENGTH, ENTROPY_THRESHOLD, ENTROPY_SEVERITY,
    FUZZY_KEYWORDS, FUZZY_THRESHOLD, FUZZY_SEVERITY,
    INVISIBLE_CHARS,
)

logger = logging.getLogger("dlp.engine")


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class DLPFinding:
    layer:       str
    category:    str
    severity:    float
    snippet:     str
    explanation: str

@dataclass
class DLPScanResult:
    decision:           str        # PASS | BLOCK
    risk_score:         float      # 0–100
    risk_tier:          str        # low | medium | high | critical
    detected_types:     List[str]
    findings:           List[dict]
    layer_scores:       Dict[str, float]
    processing_ms:      float
    block_reason:       str = ""
    from_cache:         bool = False


# ── Engine ────────────────────────────────────────────────────────────────────

class DLPEngine:
    """
    Multi-layer async DLP detection engine.
    All ML models are optional — falls back to regex when unavailable.
    """

    def __init__(self):
        self._gliner = self._load_gliner()
        self._fuzzy  = self._load_fuzzy()
        logger.info("DLPEngine ready  GLiNER=%s  RapidFuzz=%s",
                    "✓" if self._gliner else "✗ (regex fallback)",
                    "✓" if self._fuzzy  else "✗ (disabled)")

    # ── optional model loaders ────────────────────────────────────────────────

    def _load_gliner(self):
        try:
            from gliner import GLiNER
            return GLiNER.from_pretrained("urchade/gliner_medium-v2.1")
        except Exception as e:
            logger.warning("GLiNER unavailable: %s", e)
            return None

    def _load_fuzzy(self):
        try:
            from rapidfuzz import fuzz
            return fuzz
        except Exception as e:
            logger.warning("RapidFuzz unavailable: %s", e)
            return None

    # ── public API ────────────────────────────────────────────────────────────

    async def scan(
        self,
        prompt: str,
        department: str = "default",
        extra_text: str = "",
    ) -> DLPScanResult:
        start = time.perf_counter()
        combined = (prompt + "\n\n" + extra_text).strip()

        labels = [
            "credential", "financial", "pii", "confidential",
            "employee", "strategy", "entropy", "fuzzy", "obfuscated",
        ]
        weights = {
            "credential":  1.00,
            "financial":   1.00,
            "pii":         0.90,
            "confidential":0.95,
            "employee":    0.85,
            "strategy":    0.82,
            "entropy":     0.90,
            "fuzzy":       0.78,
            "obfuscated":  0.95,
        }

        # ── FAST layers (pure regex, no ML) — run concurrently ───────────────
        fast_results = await asyncio.gather(
            asyncio.to_thread(self._l1_credentials,  combined),
            asyncio.to_thread(self._l2_financial,    combined),
            asyncio.to_thread(self._l4_confidential, combined),
            asyncio.to_thread(self._l5_employee,     combined),
            asyncio.to_thread(self._l6_strategy,     combined),
            asyncio.to_thread(self._l7_entropy,      combined),
            asyncio.to_thread(self._l9_obfuscated,   combined),
        )
        fast_labels = ["credential", "financial", "confidential",
                       "employee", "strategy", "entropy", "obfuscated"]

        all_findings: List[DLPFinding] = []
        layer_scores: Dict[str, float] = {l: 0.0 for l in labels}

        for label, (findings, score) in zip(fast_labels, fast_results):
            all_findings.extend(findings)
            layer_scores[label] = round(score, 3)

        # Early-exit: if fast layers already give a definitive BLOCK, skip slow ML
        fast_max = max(
            layer_scores[lbl] * weights[lbl] for lbl in fast_labels
        )

        if fast_max < 0.50:
            # Only run slow layers (PII NER + fuzzy) when fast layers are uncertain
            slow_results = await asyncio.gather(
                asyncio.to_thread(self._l3_pii,  combined),
                asyncio.to_thread(self._l8_fuzzy, combined),
            )
            for label, (findings, score) in zip(["pii", "fuzzy"], slow_results):
                all_findings.extend(findings)
                layer_scores[label] = round(score, 3)
        else:
            # Fast definitive result — skip slow ML (PII/fuzzy won't change outcome)
            layer_scores["pii"]   = 0.0
            layer_scores["fuzzy"] = 0.0

        # Composite score
        raw = max(
            (layer_scores[lbl] * weights[lbl] for lbl in labels),
            default=0.0
        )
        risk_score = round(min(raw, 1.0) * 100, 1)

        tier = (
            "critical" if risk_score >= 80 else
            "high"     if risk_score >= 60 else
            "medium"   if risk_score >= 30 else
            "low"
        )
        # BLOCK only on high-confidence findings (score >= 55)
        # WARN for medium-risk (30–54) — avoids false-positive blocks
        decision = "BLOCK" if risk_score >= 55 else "WARN" if risk_score >= 30 else "PASS"
        detected = list({f.category for f in all_findings})
        block_reason = self._build_reason(all_findings, tier) if decision == "BLOCK" else ""

        return DLPScanResult(
            decision=decision,
            risk_score=risk_score,
            risk_tier=tier,
            detected_types=detected,
            findings=[{
                "layer":       f.layer,
                "category":    f.category,
                "severity":    round(f.severity, 3),
                "snippet":     f.snippet,
                "explanation": f.explanation,
            } for f in all_findings],
            layer_scores=layer_scores,
            processing_ms=round((time.perf_counter() - start) * 1000, 2),
            block_reason=block_reason,
        )

    # ── Layer 1: Credentials ──────────────────────────────────────────────────

    def _l1_credentials(self, text: str):
        findings, max_s = [], 0.0
        for pat, label, sev in CREDENTIAL_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "credential", label, sev, f"[{label.upper()}]",
                    f"{label} detected. Sharing credentials with external AI is a critical violation."
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 2: Financial ────────────────────────────────────────────────────

    def _luhn(self, n: str) -> bool:
        d = [int(x) for x in n if x.isdigit()]
        for i, v in enumerate(reversed(d)):
            if i % 2 == 1:
                v *= 2
                if v > 9: v -= 9
                d[-(i+1)] = v
        return sum(d) % 10 == 0

    def _l2_financial(self, text: str):
        findings, max_s = [], 0.0
        for m in CARD_REGEX.finditer(text):
            num = re.sub(r"\D", "", m.group())
            if self._luhn(num):
                findings.append(DLPFinding(
                    "financial", "Payment Card Number", 0.97,
                    f"****-****-****-{num[-4:]}",
                    "Luhn-validated payment card detected. PCI-DSS violation."
                ))
                max_s = max(max_s, 0.97)
        for pat, label, sev in FINANCIAL_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "financial", label, sev, f"[{label.upper()}]",
                    f"{label} detected. Financial identifiers must not be sent to external AI."
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 3: PII ──────────────────────────────────────────────────────────

    # Common safe words that GLiNER frequently misidentifies as PII
    _NER_ALLOWLIST = {
        "app", "cafe", "build", "want", "make", "create", "help", "need",
        "data", "user", "system", "web", "site", "api", "code", "service",
        "tool", "team", "form", "page", "list", "type", "mode", "plan",
        "bank", "card", "date", "time", "name", "test", "demo", "base",
        "work", "home", "shop", "store", "book", "chat", "open", "play",
        "note", "task", "post", "file", "link", "info", "role", "view",
    }

    def _l3_pii(self, text: str):
        findings, max_s = [], 0.0

        # Always run explicit regex patterns first (higher confidence for exact formats)
        for pat, label, sev in PII_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "pii", label, sev, f"[{label.upper()}]",
                    f"{label} detected (Hard pattern match)."
                ))
                max_s = max(max_s, sev)

        # GLiNER NER for dynamic/free-text extraction
        if self._gliner:
            try:
                # Higher threshold (0.72) — only flag high-confidence NER detections
                ents = self._gliner.predict_entities(text[:3000], PII_NER_LABELS, threshold=0.72)
                seen = set()
                for e in ents:
                    entity_text = e["text"].strip().lower()
                    # Skip allowlisted common words
                    if entity_text in self._NER_ALLOWLIST:
                        continue
                    # Skip very short tokens (1-2 chars) — likely false positives
                    if len(entity_text) <= 2:
                        continue
                    k = (e["label"], entity_text[:20])
                    if k in seen: continue
                    seen.add(k)
                    # Severity scales directly with confidence — no artificial floor
                    sev = round(e["score"] * 0.92, 3)
                    findings.append(DLPFinding(
                        "pii", e["label"].title(), sev,
                        f"[{e['label'].upper()}]",
                        f"Personal data ({e['label']}) detected at {e['score']:.0%} confidence. GDPR risk."
                    ))
                    max_s = max(max_s, sev)
            except Exception as ex:
                logger.warning("GLiNER error: %s", ex)

        return findings, max_s

    # ── Layer 4: Confidential watermarks ─────────────────────────────────────

    def _l4_confidential(self, text: str):
        findings, max_s = [], 0.0
        for pat, label, sev in CONFIDENTIAL_PATTERNS:
            m = re.search(pat, text)
            if m:
                findings.append(DLPFinding(
                    "confidential", label, sev,
                    m.group()[:80],
                    f"Confidential marker detected: '{m.group().strip()}'. Must not leave the company network."
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 5: Employee & HR data ───────────────────────────────────────────

    def _l5_employee(self, text: str):
        findings, max_s = [], 0.0
        for pat, label, sev in EMPLOYEE_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "employee", label, sev, f"[{label.upper()}]",
                    f"{label} reference detected. Employee data must not be shared with external AI."
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 6: Business strategy data ──────────────────────────────────────

    def _l6_strategy(self, text: str):
        findings, max_s = [], 0.0
        for pat, label, sev in STRATEGY_PATTERNS:
            if re.search(pat, text):
                findings.append(DLPFinding(
                    "strategy", label, sev, f"[{label.upper()}]",
                    f"{label} detected. Strategic data must not be shared externally."
                ))
                max_s = max(max_s, sev)
        return findings, max_s

    # ── Layer 7: Entropy-based secret detection ───────────────────────────────

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((v / length) * math.log2(v / length) for v in freq.values())

    def _l7_entropy(self, text: str):
        findings, max_s = [], 0.0
        # Split into candidate tokens
        for token in re.split(r"[\s\"'`=:,;\[\](){}]+", text):
            if len(token) < ENTROPY_MIN_LENGTH:
                continue
            # Skip URLs and known patterns already caught by credentials layer
            if token.startswith("http") or re.match(r"[A-Za-z]+$", token):
                continue
            entropy = self._shannon_entropy(token)
            if entropy >= ENTROPY_THRESHOLD:
                findings.append(DLPFinding(
                    "entropy", "High-Entropy Secret", ENTROPY_SEVERITY,
                    f"{token[:12]}…",
                    f"High-entropy token (Shannon={entropy:.2f} bits) — likely an API key or secret."
                ))
                max_s = max(max_s, ENTROPY_SEVERITY)
        return findings, max_s

    # ── Layer 8: Fuzzy keyword matching ──────────────────────────────────────

    def _l8_fuzzy(self, text: str):
        if not self._fuzzy:
            return [], 0.0
        findings, max_s = [], 0.0
        text_lower = text.lower()
        # Check sliding windows of 30 chars for fuzzy match
        words = text_lower.split()
        for i in range(len(words)):
            window = " ".join(words[i:i+4])
            for kw in FUZZY_KEYWORDS:
                ratio = self._fuzzy.ratio(window, kw)
                if ratio >= FUZZY_THRESHOLD:
                    findings.append(DLPFinding(
                        "fuzzy", f"Near-match: {kw.title()}", FUZZY_SEVERITY,
                        window[:60],
                        f"Fuzzy match to confidential keyword '{kw}' ({ratio:.0f}% similarity)."
                    ))
                    max_s = max(max_s, FUZZY_SEVERITY)
        return findings, max_s

    # ── Layer 9: Obfuscated / base64 ─────────────────────────────────────────

    def _l9_obfuscated(self, text: str):
        findings, max_s = [], 0.0

        # Invisible chars
        inv_count = sum(text.count(c) for c in INVISIBLE_CHARS)
        if inv_count > 2:
            sev = min(0.20 + 0.10 * inv_count, 0.85)
            findings.append(DLPFinding(
                "obfuscated", "Invisible Unicode Characters", sev,
                f"{inv_count} zero-width chars",
                "Hidden invisible characters found — may smuggle instructions or data."
            ))
            max_s = max(max_s, sev)

        # Base64 candidates — decode and re-scan
        for m in re.finditer(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/])", text):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="ignore")
                if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                    # Re-scan decoded text for credentials + financial
                    sub_findings, sub_score = self._l1_credentials(decoded)
                    sub_findings2, sub_score2 = self._l2_financial(decoded)
                    if sub_findings or sub_findings2:
                        findings.append(DLPFinding(
                            "obfuscated", "Base64-Encoded Sensitive Data", 0.95,
                            decoded[:60],
                            "Base64-encoded content contains sensitive data (credentials or financial info)."
                        ))
                        max_s = max(max_s, 0.95)
            except Exception:
                pass

        return findings, max_s

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _build_reason(findings: List[DLPFinding], tier: str) -> str:
        if not findings:
            return "Security policy violation detected."
        top = sorted(findings, key=lambda f: f.severity, reverse=True)[:3]
        cats = ", ".join(f.category for f in top)
        verb = {"critical": "critically", "high": "significantly", "medium": "potentially"}.get(tier, "")
        return (
            f"Your message {verb} violates data security policy. "
            f"Detected: {cats}. This request is blocked and logged."
        )

# Singleton
dlp_engine = DLPEngine()
