import importlib.util
from pathlib import Path
import unittest

_SECURITY_HEADERS_PATH = (
    Path(__file__).resolve().parents[5]
    / "src"
    / "baserow"
    / "contrib"
    / "builder"
    / "domains"
    / "security_headers.py"
)
_SPEC = importlib.util.spec_from_file_location(
    "builder_domain_security_headers", _SECURITY_HEADERS_PATH
)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

DEFAULT_SECURITY_HEADERS = _MODULE.DEFAULT_SECURITY_HEADERS
MAX_SECURITY_HEADER_VALUE_LENGTH = _MODULE.MAX_SECURITY_HEADER_VALUE_LENGTH
SecurityHeadersValidationError = _MODULE.SecurityHeadersValidationError
build_default_csp = _MODULE.build_default_csp
resolve_security_headers = _MODULE.resolve_security_headers
validate_security_headers = _MODULE.validate_security_headers


class SecurityHeadersTests(unittest.TestCase):
    def test_defaults_preserve_iframe_embedding_and_enable_safe_headers(self):
        resolved = resolve_security_headers()
        self.assertNotIn("X-Frame-Options", resolved)
        self.assertEqual(resolved["X-Content-Type-Options"], "nosniff")
        self.assertEqual(
            resolved["Referrer-Policy"], "strict-origin-when-cross-origin"
        )
        self.assertIn("max-age=", resolved["Strict-Transport-Security"])
        self.assertEqual(resolved, DEFAULT_SECURITY_HEADERS)

    def test_domain_headers_override_app_headers_and_inherit_others(self):
        app_headers = {
            "X-Frame-Options": "SAMEORIGIN",
            "Permissions-Policy": "geolocation=()",
        }
        domain_headers = {
            "x-frame-options": "deny",
            "Content-Security-Policy": "default-src 'self'",
        }
        resolved = resolve_security_headers(
            app_headers=app_headers, domain_headers=domain_headers
        )
        self.assertEqual(resolved["X-Frame-Options"], "DENY")
        self.assertEqual(resolved["Permissions-Policy"], "geolocation=()")
        self.assertEqual(resolved["Content-Security-Policy"], "default-src 'self'")
        self.assertEqual(resolved["X-Content-Type-Options"], "nosniff")

    def test_explicit_null_or_blank_suppresses_inherited_and_default_headers(self):
        resolved = resolve_security_headers(
            app_headers={"X-Frame-Options": "DENY"},
            domain_headers={
                "X-Frame-Options": None,
                "Strict-Transport-Security": "   ",
            },
        )
        self.assertNotIn("X-Frame-Options", resolved)
        self.assertNotIn("Strict-Transport-Security", resolved)
        self.assertEqual(resolved["X-Content-Type-Options"], "nosniff")

    def test_validate_normalizes_canonical_names_and_values(self):
        normalized = validate_security_headers(
            {
                "x-frame-options": " sameorigin ",
                "x-content-type-options": "NOSNIFF",
                "referrer-policy": "no-referrer-when-downgrade",
                "permissions-policy": "",
            }
        )
        self.assertEqual(
            normalized,
            {
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer-when-downgrade",
                "Permissions-Policy": None,
            },
        )

    def test_validate_rejects_injection_unknown_headers_and_invalid_values(self):
        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers(["not-a-dict"])

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers({"Set-Cookie": "admin=1"})

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers({"Content-Security-Policy": "default-src 'self'\r\nX-Evil: 1"})

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers({"Content-Security-Policy": "default-src 'self'\x00"})

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers({"X-Frame-Options": "ALLOWALL"})

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers({"X-Content-Type-Options": "invalid"})

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers(
                {"Referrer-Policy": "origin", "referrer-policy": "no-referrer"}
            )

        with self.assertRaises(SecurityHeadersValidationError):
            validate_security_headers(
                {"Content-Security-Policy": "a" * (MAX_SECURITY_HEADER_VALUE_LENGTH + 1)}
            )

    def test_build_default_csp(self):
        csp = build_default_csp(
            api_origin="https://api.example.com",
            frame_ancestors="'self' https://portal.example.com",
        )
        self.assertEqual(
            csp,
            "connect-src 'self' https://api.example.com; "
            "frame-ancestors 'self' https://portal.example.com",
        )


if __name__ == "__main__":
    unittest.main()
