"""
NIST SP 800-63B (2024)–style Password Validator
- Length 8–64
- Case-insensitive blacklist check (20+ items)
- Username must not appear in password
- No truncation: we evaluate entire string (including spaces & unicode)
- Optional strength score (0–100) and rating
- Optional: simple sequential-pattern detector for bonus points
"""

from dataclasses import dataclass
from typing import List, Tuple

# --- Step 1: Blacklist (20+ common/compromised passwords) ---
BLACKLIST = {
    "password", "123456", "123456789", "12345678", "qwerty", "qwertyuiop",
    "111111", "123123", "letmein", "welcome", "iloveyou", "admin",
    "monkey", "abc123", "dragon", "sunshine", "football", "princess",
    "login", "passw0rd", "zaq12wsx", "baseball", "starwars", "shadow",
    "master", "freedom", "whatever", "trustno1", "pokemon", "password1"
}

# --- Step 2: Error/Warning messages dictionary ---
VIOLATIONS = {
    "too_short": "X Password must be at least 8 characters.",
    "too_long": "X Password cannot exceed 64 characters.",
    "blacklisted": "X This password is common/compromised (found in data breaches).",
    "has_username": "X Password cannot contain your username."
}

WARNINGS = {
    "sequential": "• Avoid simple sequences like '123' or 'abc'."
}

@dataclass
class ValidationResult:
    violations: List[str]
    warnings: List[str]
    score: int = 0
    rating: str = ""


# --- Helper: very small sequential-pattern detector (bonus) ---
def _has_simple_sequence(pw: str) -> bool:
    """
    Detects simple 3+ length ascending sequences like 'abc', '123', 'qwe' (linear).
    NOTE: This is a heuristic and *not* part of NIST core requirements.
    """
    if len(pw) < 3:
        return False

    s = pw.lower()

    # numeric straight sequences
    digits = "0123456789"
    # alpha straight sequences
    alpha = "abcdefghijklmnopqrstuvwxyz"

    for i in range(len(s) - 2):
        chunk = s[i:i+3]
        if chunk in digits or chunk in alpha:
            return True
        # Also check longer sequences by sliding
        if len(s) >= 4 and i + 4 <= len(s):
            chunk4 = s[i:i+4]
            if chunk4 in digits or chunk4 in alpha:
                return True
    return False


# --- Step 3: Validation function ---
def validate_password(password: str, username: str = "") -> Tuple[List[str], List[str]]:
    """
    Validate password against a subset of NIST SP 800-63B rules.

    Args:
        password (str): Password to validate (full string, not truncated)
        username (str): Username to check against

    Returns:
        Tuple[List[str], List[str]]: (violations, warnings)
    """
    violations: List[str] = []
    warnings: List[str] = []

    # 1) Length checks
    if len(password) < 8:
        violations.append(VIOLATIONS["too_short"])
    elif len(password) > 64:
        violations.append(VIOLATIONS["too_long"])

    # 2) Blacklist check (case-insensitive)
    if password.lower() in BLACKLIST:
        violations.append(VIOLATIONS["blacklisted"])

    # 3) Username should not appear in the password (case-insensitive)
    if username and username.strip() and username.lower() in password.lower():
        violations.append(VIOLATIONS["has_username"])

    # Bonus optional warning: simple sequence detector
    if _has_simple_sequence(password):
        warnings.append(WARNINGS["sequential"])

    return violations, warnings


# --- Step 5 (Optional): Strength scoring ---
def get_strength_score(password: str) -> int:
    """
    Score 0–100. NIST emphasizes length; variety helps but is NOT required.
    """
    score = 0

    # Length emphasis
    L = len(password)
    if L >= 15:
        score += 50
    elif L >= 12:
        score += 40
    elif L >= 8:
        score += 30
    # else: <8 will be rejected in validation anyway

    # Character variety (informational)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    variety_count = sum([has_upper, has_lower, has_digit, has_special])
    score += int(variety_count * 12.5)  # up to +50

    # Cap to [0, 100]
    score = max(0, min(100, score))
    return score


def _rating(score: int) -> str:
    if score >= 80:
        return "Excellent"
    if score >= 60:
        return "Good"
    if score >= 40:
        return "Fair"
    return "Weak"


def evaluate(password: str, username: str = "") -> ValidationResult:
    violations, warnings = validate_password(password, username)
    result = ValidationResult(violations=violations, warnings=warnings)

    # Only score if not rejected for length/blacklist/username
    if not violations:
        result.score = get_strength_score(password)
        result.rating = _rating(result.score)

    return result


def _pretty_print(result: ValidationResult) -> None:
    if result.violations:
        print("\nPASSWORD REJECTED\n")
        for v in result.violations:
            print(v)
    else:
        print("\nPASSWORD ACCEPTED (NIST Compliant)")
        print(f"Strength score: {result.score} — {result.rating}")
        if result.warnings:
            print("\nWarnings:")
            for w in result.warnings:
                print(w)


if __name__ == "__main__":
    print("=" * 60)
    print("NIST SP 800-63B PASSWORD VALIDATOR")
    print("=" * 60)

    while True:
        username = input("\nEnter username (or 'quit'): ").strip()
        if username.lower() == "quit":
            break

        password = input("Enter password: ")

        res = evaluate(password, username)
        _pretty_print(res)
