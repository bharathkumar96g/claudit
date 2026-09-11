import pytest

from claudit.detect import luhn_ok, mask, redact, scan

# Built from parts so the repo's own secret scanner doesn't flag the fixtures.
POSITIVE = {
    "anthropic_api_key": "ANTHROPIC_API_KEY=sk-ant-api03-" + "a1B2" * 20,
    "openai_api_key": "key sk-proj-" + "Zx9k" * 12,
    "aws_access_key_id": "AWS_ACCESS_KEY_ID=AKIA" + "IOSFODNN7EXAMPLE",
    "aws_secret_access_key": "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
    "github_token": "GITHUB_TOKEN=ghp_" + "A1b2C3d4" * 5,
    "slack_token": "xoxb-" + "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx",
    "google_api_key": "AIza" + "Sy" * 17 + "Q",
    "stripe_key": "STRIPE_SECRET_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "jwt": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "ssn": "SSN: 219-09-9999",
    "credit_card": "card 4111 1111 1111 1111",
    "generic_secret": 'DB_PASSWORD = "Tr0ub4dor&3xyz!"',
    "email": "contact priya.nair@northwind-freight.com",
    "phone": "call (214) 555-0143",
    "high_entropy_string": "token was Q7v3ZpL9xK2mN8bT4wR6yH1cJ5dF0gS3aU7eW9",
    "private_key": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow\n-----END RSA " + "PRIVATE KEY-----",
    "connection_string": "DATABASE_URL=postgresql://app:s3cretPW@db.internal:5432/prod",
}

NEGATIVE = [
    "commit 3f2a9c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39",
    "request_id=550e8400-e29b-41d4-a716-446655440000",
    "API_KEY=your_api_key_here",
    'password = os.environ["DB_PASSWORD"]',
    "Co-Authored-By: Claude <noreply@anthropic.com>",
    '"timestamp": 1694300000000',
    "max_tokens=4096",
    "token: true",
    "/Users/demo/projects/claudit/src/claudit/detect.py",
    "order 2024-000123 total 1234.56",
    "ThisIsAVeryLongCamelCaseIdentifierWithoutDigits",
]


@pytest.mark.parametrize(("category", "text"), POSITIVE.items())
def test_detects_each_category_exactly_once(category, text):
    matches = scan(text)
    assert [m.category for m in matches] == [category]


@pytest.mark.parametrize("text", NEGATIVE)
def test_ignores_benign_text(text):
    assert scan(text) == []


def test_specific_rule_beats_generic_on_overlap():
    text = "OPENAI_API_KEY=sk-proj-" + "Zx9k" * 12
    matches = scan(text)
    assert len(matches) == 1 and matches[0].category == "openai_api_key"


def test_redact_replaces_only_the_secret():
    secret = "sk-ant-api03-" + "q9Wz" * 20
    text = f"key={secret} done"
    out = redact(text, scan(text))
    assert secret not in out
    assert out == "key=[REDACTED:anthropic_api_key] done"


def test_preview_never_reveals_value():
    secret = "ghp_" + "A1b2C3d4" * 5
    m = scan(f"token {secret}")[0]
    assert m.preview != secret and len(m.preview) < len(secret)
    assert mask("short", "generic_secret") == "*****"
    assert len(m.fingerprint) == 64


def test_luhn():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")
