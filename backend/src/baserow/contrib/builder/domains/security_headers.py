from typing import Dict, Mapping, Optional

MAX_SECURITY_HEADER_VALUE_LENGTH = 4096

CANONICAL_SECURITY_HEADERS: Dict[str, str] = {
    "strict-transport-security": "Strict-Transport-Security",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "permissions-policy": "Permissions-Policy",
}

# Defaults intentionally omit X-Frame-Options because published Baserow sites
# support embedding inside external iframes unless opted out per app or domain.
DEFAULT_SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

ALLOWED_X_FRAME_OPTIONS = {"DENY", "SAMEORIGIN"}
ALLOWED_X_CONTENT_TYPE_OPTIONS = {"nosniff"}


class SecurityHeadersValidationError(ValueError):
    """Raised when a configured security headers mapping fails validation."""

    def __init__(self, errors: Mapping[str, list[str]]):
        self.errors = dict(errors)
        super().__init__(str(self.errors))


def _contains_control_chars(value: str) -> bool:
    return "\r" in value or "\n" in value or "\x00" in value


def validate_security_headers(value: object) -> Dict[str, Optional[str]]:
    """
    Validate and normalize a per-app or per-domain security_headers mapping.

    Values may be strings or ``None`` (or empty string, normalized to ``None``)
    to explicitly suppress an inherited default or app-level header.
    """

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise SecurityHeadersValidationError(
            {"security_headers": ["Security headers must be a JSON object."]}
        )

    normalized: Dict[str, Optional[str]] = {}
    errors: Dict[str, list[str]] = {}

    for raw_key, raw_val in value.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            errors.setdefault("security_headers", []).append(
                "Header names must be non-empty strings."
            )
            continue

        canonical_key = CANONICAL_SECURITY_HEADERS.get(raw_key.strip().lower())
        if canonical_key is None:
            errors.setdefault(raw_key, []).append(
                f"Unsupported security header '{raw_key}'. Allowed headers: "
                + ", ".join(CANONICAL_SECURITY_HEADERS.values())
                + "."
            )
            continue

        if canonical_key in normalized:
            errors.setdefault(canonical_key, []).append(
                f"Duplicate configuration for header '{canonical_key}'."
            )
            continue

        if raw_val is None:
            normalized[canonical_key] = None
            continue

        if not isinstance(raw_val, str):
            errors.setdefault(canonical_key, []).append(
                f"Value for '{canonical_key}' must be a string or null."
            )
            continue

        if _contains_control_chars(raw_val):
            errors.setdefault(canonical_key, []).append(
                f"Value for '{canonical_key}' cannot contain newline or null bytes."
            )
            continue

        cleaned_val = raw_val.strip()
        if not cleaned_val:
            normalized[canonical_key] = None
            continue

        if len(cleaned_val) > MAX_SECURITY_HEADER_VALUE_LENGTH:
            errors.setdefault(canonical_key, []).append(
                f"Value for '{canonical_key}' exceeds "
                f"{MAX_SECURITY_HEADER_VALUE_LENGTH} characters."
            )
            continue

        if canonical_key == "X-Frame-Options":
            upper_val = cleaned_val.upper()
            if upper_val not in ALLOWED_X_FRAME_OPTIONS:
                errors.setdefault(canonical_key, []).append(
                    "X-Frame-Options must be 'DENY' or 'SAMEORIGIN'."
                )
                continue
            cleaned_val = upper_val
        elif canonical_key == "X-Content-Type-Options":
            lower_val = cleaned_val.lower()
            if lower_val not in ALLOWED_X_CONTENT_TYPE_OPTIONS:
                errors.setdefault(canonical_key, []).append(
                    "X-Content-Type-Options must be 'nosniff'."
                )
                continue
            cleaned_val = lower_val

        normalized[canonical_key] = cleaned_val

    if errors:
        raise SecurityHeadersValidationError(errors)

    return normalized


def build_default_csp(
    *,
    api_origin: Optional[str] = None,
    frame_ancestors: Optional[str] = None,
) -> str:
    """
    Build a helper Content-Security-Policy directive string targeting the configured
    Baserow API origin and optional frame-ancestors policy.
    """

    directives = []
    if api_origin:
        directives.append(f"connect-src 'self' {api_origin}")
    if frame_ancestors:
        directives.append(f"frame-ancestors {frame_ancestors}")
    return "; ".join(directives)


def resolve_security_headers(
    app_headers: Optional[Mapping[str, Optional[str]]] = None,
    domain_headers: Optional[Mapping[str, Optional[str]]] = None,
) -> Dict[str, str]:
    """
    Merge default security headers with per-app and per-domain overrides.

    Precedence order (highest first): domain_headers -> app_headers -> defaults.
    Setting a header value to ``None`` (or empty string) suppresses that header
    in the returned response mapping.
    """

    merged: Dict[str, Optional[str]] = dict(DEFAULT_SECURITY_HEADERS)
    for layer in (app_headers, domain_headers):
        if not layer:
            continue
        normalized_layer = validate_security_headers(layer)
        for header_name, header_value in normalized_layer.items():
            if header_value is None:
                merged.pop(header_name, None)
            else:
                merged[header_name] = header_value

    return {k: v for k, v in merged.items() if v is not None}
