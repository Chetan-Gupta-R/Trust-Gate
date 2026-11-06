from typing import Any


DEFAULT_POLICY = {
    "max_auto_payment_inr": 10000,
    "require_verified_vendor": True,
    "require_bank_match": True,
    "block_prompt_injection": True,
}


def evaluate_policy(checks: dict[str, Any], prompt_injection_detected: bool) -> dict[str, Any]:
    """Enforce mandatory backend authorization checks and report each result."""
    policy_checks = {
        "vendor_verified": checks["vendor_verified"],
        "vendor_name_match": checks["vendor_name_match"],
        "source_text_present": checks["source_text_present"],
        "beneficiary_match": checks["beneficiary_match"],
        "amount_valid": checks["amount_valid"],
        "currency_supported": checks["currency_supported"],
        "amount_within_limit": checks["amount_within_limit"],
        "action_supported": checks["action_supported"],
        "trusted_bank_available": checks["trusted_bank_available"],
        "policy_valid": checks["policy_valid"],
        "prompt_injection_detected": prompt_injection_detected,
    }
    reasons = [
        name
        for name, passed in policy_checks.items()
        if (name == "prompt_injection_detected" and passed)
        or (name != "prompt_injection_detected" and not passed)
    ]

    return {
        "decision": "BLOCK" if reasons else "ALLOW",
        "policy_checks": policy_checks,
        "failed_checks": reasons,
    }
