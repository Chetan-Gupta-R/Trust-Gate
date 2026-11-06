import math
import re
from numbers import Real
from typing import Any

try:
    from .injection_detector import detect_prompt_injection
    from .policy_engine import DEFAULT_POLICY, evaluate_policy
except ImportError:
    from injection_detector import detect_prompt_injection
    from policy_engine import DEFAULT_POLICY, evaluate_policy


_SCORE_WEIGHTS = {
    "prompt_injection": 38,
    "concealment": 20,
    "beneficiary_mismatch": 25,
    "vendor_verification_failure": 30,
    "amount_over_limit": 15,
    "invalid_action": 40,
    "missing_document_text": 30,
}


def _normalized_name(value: Any) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold() if isinstance(value, str) else ""


def _trusted_bank(context: dict[str, Any]) -> tuple[str, str]:
    bank_record = context.get("verified_bank")
    if isinstance(bank_record, dict):
        return (
            bank_record.get("bank_name", ""),
            bank_record.get("account_last4", ""),
        )
    return context.get("bank_name", ""), context.get("account_last4", "")


def _positive_number(value: Any) -> bool:
    return (
        isinstance(value, Real)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and value > 0
    )


def _effective_limit(policy: dict[str, Any]) -> tuple[float, bool]:
    supplied_limit = policy.get(
        "max_auto_payment_inr",
        policy.get("maximum_automatic_payment_inr"),
    )
    if supplied_limit is None:
        return float(DEFAULT_POLICY["max_auto_payment_inr"]), True
    if not _positive_number(supplied_limit):
        return float(DEFAULT_POLICY["max_auto_payment_inr"]), False
    # Client policy can make the server default stricter, never more permissive.
    return min(float(supplied_limit), float(DEFAULT_POLICY["max_auto_payment_inr"])), True


def _risk_label(score: int) -> str:
    if score < 20:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"


def analyze_request(request: dict[str, Any]) -> dict[str, Any]:
    """Calculate an authorization decision from untrusted input and trusted records."""
    source = request.get("source")
    trusted_context = request.get("trusted_context")
    proposed_action = request.get("proposed_action")
    policy = request.get("policy")

    source = source if isinstance(source, dict) else {}
    trusted_context = trusted_context if isinstance(trusted_context, dict) else {}
    proposed_action = proposed_action if isinstance(proposed_action, dict) else {}
    policy = policy if isinstance(policy, dict) else {}

    document_text = source.get("document_text", source.get("text", ""))
    source_text_present = isinstance(document_text, str) and bool(document_text.strip())
    injection = detect_prompt_injection(document_text)
    trusted_bank, trusted_account = _trusted_bank(trusted_context)
    proposed_bank = proposed_action.get("beneficiary_bank", "")
    proposed_account = proposed_action.get("beneficiary_account_last4", "")
    proposed_vendor = proposed_action.get("vendor_name", "")
    trusted_vendor = trusted_context.get("vendor_name", "")
    action_type = proposed_action.get("type", proposed_action.get("action_type"))
    amount = proposed_action.get(
        "amount_inr",
        proposed_action.get("amount"),
    )
    currency_supported = (
        proposed_action.get("currency", "INR") == "INR"
        if "amount_inr" in proposed_action
        else proposed_action.get("currency") == "INR"
    )

    verification_marker = trusted_context.get(
        "vendor_verified",
        trusted_context.get("verified"),
    )
    if verification_marker is None:
        verification_marker = bool(
            isinstance(trusted_context.get("verified_gstin"), str)
            and trusted_context["verified_gstin"].strip()
        )

    vendor_verified = verification_marker is True
    vendor_name_match = bool(
        _normalized_name(proposed_vendor)
        and _normalized_name(trusted_vendor)
        and _normalized_name(proposed_vendor) == _normalized_name(trusted_vendor)
    )
    trusted_bank_available = (
        isinstance(trusted_bank, str)
        and bool(trusted_bank.strip())
        and isinstance(trusted_account, str)
        and bool(re.fullmatch(r"\d{4}", trusted_account.strip()))
    )
    beneficiary_match = bool(
        trusted_bank_available
        and isinstance(proposed_bank, str)
        and _normalized_name(proposed_bank) == _normalized_name(trusted_bank)
        and isinstance(proposed_account, str)
        and re.fullmatch(r"\d{4}", proposed_account.strip() or "") is not None
        and proposed_account.strip() == trusted_account.strip()
    )
    amount_valid = _positive_number(amount)
    action_supported = isinstance(action_type, str) and action_type.upper() == "PAY_INVOICE"
    effective_limit, policy_valid = _effective_limit(policy)
    amount_within_limit = amount_valid and amount <= effective_limit
    vendor_check = vendor_verified and vendor_name_match

    checks = {
        "vendor_verified": vendor_check,
        "vendor_name_match": vendor_name_match,
        "source_text_present": source_text_present,
        "beneficiary_match": beneficiary_match,
        "amount_valid": amount_valid,
        "currency_supported": currency_supported,
        "amount_within_limit": amount_within_limit,
        "action_supported": action_supported,
        "trusted_bank_available": trusted_bank_available,
        "policy_valid": policy_valid,
    }
    policy_result = evaluate_policy(checks, injection["detected"])
    decision = policy_result["decision"]

    risk_factors = {
        "prompt_injection": injection["detected"],
        "concealment": injection["concealment_detected"],
        "beneficiary_mismatch": not beneficiary_match,
        "vendor_verification_failure": not vendor_check,
        "amount_over_limit": amount_valid and not amount_within_limit,
        "invalid_action": not action_supported or not amount_valid or not currency_supported,
        "missing_document_text": not source_text_present,
    }
    risk_score = min(
        100,
        sum(
            _SCORE_WEIGHTS[name] for name, triggered in risk_factors.items() if triggered
        ),
    )
    risk_breakdown = {
        name: {
            "triggered": triggered,
            "points": _SCORE_WEIGHTS[name] if triggered else 0,
        }
        for name, triggered in risk_factors.items()
    }

    evidence: list[str] = []
    if injection["detected"]:
        evidence.append("Prompt injection instruction detected.")
    if not source_text_present:
        evidence.append("Invoice document text is missing or malformed.")
    if injection["concealment_detected"]:
        evidence.append("Concealment instruction detected.")
    if not vendor_verified:
        evidence.append("Trusted vendor verification is missing or failed.")
    if not vendor_name_match:
        evidence.append("Proposed vendor name does not match the trusted vendor record.")
    if trusted_bank_available:
        evidence.append(f"Trusted bank: {trusted_bank.strip()}.")
        evidence.append(f"Trusted account ending: {trusted_account.strip()}.")
    else:
        evidence.append("Trusted bank or account ending is missing or malformed.")
    if isinstance(proposed_bank, str) and proposed_bank.strip():
        evidence.append(f"Proposed bank: {proposed_bank.strip()}.")
    else:
        evidence.append("Proposed beneficiary bank is missing.")
    if isinstance(proposed_account, str) and re.fullmatch(r"\d{4}", proposed_account.strip()):
        evidence.append(f"Proposed account ending: {proposed_account.strip()}.")
    else:
        evidence.append("Proposed beneficiary account ending is missing or malformed.")
    if trusted_bank_available and not beneficiary_match:
        evidence.append(
            "Beneficiary mismatch: proposed bank/account does not match the trusted vendor record."
        )
    if amount_valid:
        evidence.append(f"Invoice amount: INR {amount:g}.")
    else:
        evidence.append("Invoice amount is invalid; it must be a positive finite number.")
    if not currency_supported:
        evidence.append("Payment currency must be INR.")
    evidence.append(f"Automatic payment threshold: INR {effective_limit:g}.")
    if not amount_within_limit and amount_valid:
        evidence.append("Amount exceeds the automatic authorization limit; human approval is required.")
    if not action_supported:
        evidence.append("Proposed action type is missing or unsupported.")
    if not policy_valid:
        evidence.append("Supplied payment threshold is invalid; authorization failed closed.")
    active_factors = [
        f"{_SCORE_WEIGHTS[name]} {name.replace('_', ' ')} points"
        for name, triggered in risk_factors.items()
        if triggered
    ]
    if active_factors:
        evidence.append("Risk factors: " + ", ".join(active_factors) + ".")
    evidence.append("Payment execution was not attempted.")

    blocked_reasons: list[str] = []
    if injection["detected"]:
        blocked_reasons.append("prompt injection was detected")
    if not source_text_present:
        blocked_reasons.append("invoice document text is missing or malformed")
    if not vendor_check:
        blocked_reasons.append("trusted vendor verification or vendor name matching failed")
    if not trusted_bank_available:
        blocked_reasons.append("trusted beneficiary data is missing or malformed")
    elif not beneficiary_match:
        blocked_reasons.append("the proposed beneficiary does not match the trusted bank record")
    if not amount_valid:
        blocked_reasons.append("the payment amount is invalid")
    if not currency_supported:
        blocked_reasons.append("the payment currency is not INR")
    if amount_valid and not amount_within_limit:
        blocked_reasons.append("the amount exceeds the automatic payment limit and requires human approval")
    if not action_supported:
        blocked_reasons.append("the proposed action type is unsupported")
    if not policy_valid:
        blocked_reasons.append("the supplied payment policy is invalid")

    summary = (
        "Authorization allowed: all backend vendor, beneficiary, amount, and document checks passed."
        if decision == "ALLOW"
        else "Blocked because " + "; ".join(blocked_reasons) + "."
    )

    return {
        "decision": decision,
        "risk": _risk_label(risk_score),
        "risk_score": risk_score,
        "risk_factors": risk_breakdown,
        "threat_analysis": {
            "prompt_injection_detected": injection["detected"],
            "summary": summary,
            "matched_patterns": injection["matched_patterns"],
            "suspicious_instructions": injection["suspicious_instructions"],
            "evidence": injection["evidence"],
            "concealment_detected": injection["concealment_detected"],
        },
        "policy_checks": policy_result["policy_checks"],
        "execution": {
            "attempted": False,
            "executed": False,
            "status": "NOT_EXECUTED",
            "message": "TrustGate evaluates authorization only; no payment was attempted.",
        },
        "evidence": evidence,
    }
