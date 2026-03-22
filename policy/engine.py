"""
DLP Gateway — Policy Engine
Loads department/role policies from policies.yaml and makes PASS/BLOCK decisions
based on the detected categories from the DLP engine.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List

import yaml

logger = logging.getLogger("dlp.policy")

POLICY_FILE = Path(__file__).parent / "policies.yaml"


class PolicyEngine:
    def __init__(self, policy_file: Path = POLICY_FILE):
        self._policies = self._load(policy_file)
        logger.info("PolicyEngine loaded %d department policies", len(self._policies))

    def _load(self, path: Path) -> dict:
        try:
            with open(path) as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning("Could not load policies.yaml: %s — using defaults", e)
            return {}

    def evaluate(
        self,
        department: str,
        role: str,
        detected_types: List[str],
        risk_score: float,
    ) -> dict:
        """
        Returns a dict with:
          - decision: PASS | BLOCK | WARN
          - triggered_rules: list of matched policy rules
          - overridden: True if policy upgraded the scanner's PASS to a BLOCK
        """
        dept_policy = (
            self._policies.get(department.lower())
            or self._policies.get("default")
            or {}
        )
        block_types = set(dept_policy.get("block", []))
        warn_types  = set(dept_policy.get("warn", []))

        # Normalize detected types to lowercase underscored keys
        detected_normalized = {d.lower().replace(" ", "_") for d in detected_types}

        triggered_block = detected_normalized & block_types
        triggered_warn  = detected_normalized & warn_types

        if triggered_block or risk_score >= 80:
            decision = "BLOCK"
        elif triggered_warn or risk_score >= 40:
            decision = "WARN"
        else:
            decision = "PASS"

        return {
            "decision":       decision,
            "triggered_block": list(triggered_block),
            "triggered_warn":  list(triggered_warn),
            "overridden":      bool(triggered_block and risk_score < 30),
        }


policy_engine = PolicyEngine()
