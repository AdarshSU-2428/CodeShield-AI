from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.enums import Confidence, FindingCategory, Severity
from app.core.models.audit import AuditFinding, AuditReport


class FindingValidator:
    """
    US 19: Enforces strict canonical schema validation, type safety, coordinate integrity,
    and consistency on all audit findings across AI and static analysis engines.
    """

    REQUIRED_FINDING_FIELDS = {
        "title",
        "description",
        "category",
        "severity",
        "confidence",
        "file_path",
        "start_line",
        "end_line",
    }

    VALID_SEVERITIES = {s.value for s in Severity}
    VALID_CONFIDENCES = {c.value for c in Confidence}
    VALID_CATEGORIES = {cat.value for cat in FindingCategory}

    def validate_finding(
        self,
        finding: Union[AuditFinding, Dict[str, Any]],
    ) -> Tuple[bool, List[str]]:
        """
        Validate that a finding complies strictly with the canonical CodeShield schema.
        Returns: (is_valid: bool, validation_errors: List[str])
        """
        errors: List[str] = []
        data = finding.to_dict() if isinstance(finding, AuditFinding) else finding

        if not isinstance(data, dict):
            return False, ["Finding payload must be a dictionary or AuditFinding instance."]

        # 1. Mandatory field presence and non-emptiness
        for field in self.REQUIRED_FINDING_FIELDS:
            val = data.get(field)
            if val is None or (isinstance(val, str) and not val.strip()):
                errors.append(f"Missing mandatory field: '{field}'")

        # 2. Coordinate integrity (1-indexed, end_line >= start_line)
        start_line = data.get("start_line")
        end_line = data.get("end_line")

        if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
            errors.append(f"Invalid start_line ({start_line}); must be integer >= 1.")

        if not isinstance(end_line, int) or isinstance(end_line, bool) or end_line < 1:
            errors.append(f"Invalid end_line ({end_line}); must be integer >= 1.")

        if isinstance(start_line, int) and isinstance(end_line, int) and not isinstance(start_line, bool) and not isinstance(end_line, bool):
            if end_line < start_line:
                errors.append(f"Inconsistent line coordinates: end_line ({end_line}) < start_line ({start_line}).")

        # 3. Enum value validity
        sev = str(data.get("severity") or "").lower()
        if sev not in self.VALID_SEVERITIES:
            errors.append(f"Invalid severity '{sev}'; must be one of {sorted(self.VALID_SEVERITIES)}.")

        conf = str(data.get("confidence") or "").lower()
        if conf not in self.VALID_CONFIDENCES:
            errors.append(f"Invalid confidence '{conf}'; must be one of {sorted(self.VALID_CONFIDENCES)}.")

        cat = str(data.get("category") or "").lower()
        if cat not in self.VALID_CATEGORIES:
            errors.append(f"Invalid category '{cat}'; must be one of {sorted(self.VALID_CATEGORIES)}.")

        # 4. Risk score bounds [0.0, 10.0]
        risk_score = data.get("risk_score")
        if risk_score is not None:
            if not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool):
                errors.append(f"Invalid risk_score '{risk_score}'; must be numeric.")
            elif not (0.0 <= float(risk_score) <= 10.0):
                errors.append(f"risk_score '{risk_score}' out of bounds [0.0, 10.0].")

        # 5. Remediation steps and evidence must be structured
        rem_steps = data.get("remediation_steps")
        if rem_steps is not None and not isinstance(rem_steps, list):
            errors.append("remediation_steps must be a list of actionable strings.")

        evidence = data.get("evidence")
        if evidence is not None and not isinstance(evidence, dict):
            errors.append("evidence must be a structured key-value dictionary.")

        return len(errors) == 0, errors

    def normalize_raw_finding(
        self,
        raw: Dict[str, Any],
        default_file: str = "unknown",
    ) -> AuditFinding:
        """
        Sanitize and normalize an unstructured or loose AI response into a valid AuditFinding.
        Coerces strings to integers, handles None values, and clamps invalid coordinates.
        """
        title = str(raw.get("title") or "Potential Code Security Flaw").strip()
        description = str(raw.get("description") or "Unspecified issue identified by analyzer.").strip()

        # Severity coercion
        raw_sev = str(raw.get("severity") or "").lower().strip()
        sev = Severity.MEDIUM
        for s in Severity:
            if s.value == raw_sev:
                sev = s
                break

        # Confidence coercion
        raw_conf = str(raw.get("confidence") or "").lower().strip()
        conf = Confidence.MEDIUM
        for c in Confidence:
            if c.value == raw_conf:
                conf = c
                break

        # Category coercion
        raw_cat = str(raw.get("category") or "").lower().strip()
        cat = FindingCategory.SECURITY
        for k in FindingCategory:
            if k.value == raw_cat:
                cat = k
                break

        # Line coordinate coercion
        def _safe_pos_int(v: Any, fallback: int = 1) -> int:
            if isinstance(v, bool):
                return fallback
            try:
                num = int(v)
                return max(1, num)
            except (ValueError, TypeError):
                return fallback

        start_line = _safe_pos_int(raw.get("start_line"), 1)
        end_line = _safe_pos_int(raw.get("end_line"), start_line)
        if end_line < start_line:
            end_line = start_line

        file_path = str(raw.get("file_path") or raw.get("file") or default_file).strip()

        # Evidence dictionary
        raw_evidence = raw.get("evidence")
        evidence = raw_evidence if isinstance(raw_evidence, dict) else {}

        # Remediation steps list
        raw_steps = raw.get("remediation_steps")
        if isinstance(raw_steps, list):
            steps = [str(s).strip() for s in raw_steps if str(s).strip()]
        elif isinstance(raw_steps, str) and raw_steps.strip():
            steps = [raw_steps.strip()]
        else:
            steps = []

        return AuditFinding(
            title=title,
            description=description,
            category=cat,
            severity=sev,
            confidence=conf,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            code_snippet=raw.get("code_snippet") or raw.get("snippet"),
            cwe_id=raw.get("cwe_id"),
            recommendation=raw.get("recommendation"),
            source=str(raw.get("source") or "ai_analyzer"),
            evidence=evidence,
            risk_explanation=raw.get("risk_explanation"),
            exploit_scenario=raw.get("exploit_scenario"),
            remediation_code=raw.get("remediation_code"),
            remediation_steps=steps,
        )

    def validate_report(self, report: AuditReport) -> Tuple[bool, List[str]]:
        """Validate all findings and summary metrics within a consolidated AuditReport."""
        all_errors: List[str] = []

        if not report.job_id:
            all_errors.append("AuditReport must have a valid non-empty job_id.")
        if not report.project_id:
            all_errors.append("AuditReport must have a valid non-empty project_id.")

        for idx, finding in enumerate(report.findings):
            is_valid, errors = self.validate_finding(finding)
            if not is_valid:
                for err in errors:
                    all_errors.append(f"Finding #{idx + 1} ('{finding.title}'): {err}")

        return len(all_errors) == 0, all_errors