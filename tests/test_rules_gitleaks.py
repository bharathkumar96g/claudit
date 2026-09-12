from claudit.detect import GITLEAKS_FAILED, GITLEAKS_RULES, RULES, scan
from claudit.rules_gitleaks import SKIP


def test_gitleaks_rules_load():
    assert len(GITLEAKS_RULES) >= 190
    assert GITLEAKS_FAILED == []
    ids = {r.category for r in GITLEAKS_RULES}
    assert SKIP.isdisjoint(ids)
    assert all(r.source == "gitleaks" and r.keywords for r in GITLEAKS_RULES)


def test_imported_vendor_formats_detect():
    cases = {
        "npm-access-token": "NPM_TOKEN=npm_" + "a1B2c3D4e5F6" * 3,
        "gitlab-pat": "GITLAB_TOKEN=glpat-" + "Zx9kQ2mN7pL4vR8t" + "AbCd",
        "databricks-api-token": "DATABRICKS_TOKEN=dapi" + "0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c",
        "huggingface-access-token": "HF_TOKEN=hf_" + "QmZxKpLwRtNvHsJdGcYbFaUeOiTnMkWpZx",
        "openshift-user-token": "token: sha256~" + "Zx9kQ2mN7pL4vR8tAbCdEfGh1JkLmNoPqRsTuVwXyZ0",
        "sendgrid-api-token": "SENDGRID_API_KEY=SG." + "aB3dE5fG7hI9jK1lM2nO4p" + "." + "qR6sT8uV0wX2yZ4aB6cD8eF0gH2iJ4kL6mN8oP0qR2s",
    }
    for category, text in cases.items():
        found = [m.category for m in scan(text)]
        assert found == [category], (category, found)


def test_claudit_rules_win_over_imported_duplicates():
    text = "GITHUB_TOKEN=ghp_" + "A1b2C3d4" * 5
    matches = scan(text)
    assert [m.category for m in matches] == ["github_token"]


def test_mid_pattern_flag_rules_were_repaired():
    # sendgrid's pattern has a Go-style mid-pattern (?i); it must load and match lowercase tails.
    by_id = {r.category: r for r in GITLEAKS_RULES}
    assert "sendgrid-api-token" in by_id and "linear-api-key" in by_id
    assert scan("LINEAR_API_KEY=lin_api_" + "abcdef0123456789abcdef0123456789abcdefab")[0].category == "linear-api-key"


def test_keyword_prefilter_skips_rules_without_their_keyword():
    # A digest that would satisfy databricks' regex shape but lacks the 'dapi' keyword never reaches the regex.
    assert scan("digest 0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c") == []
    assert len(RULES) > 200


def test_global_stopwords_reject_alphabet_shaped_values():
    assert scan("HF_TOKEN=hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh") == [] or all(
        m.category != "huggingface-access-token" for m in scan("HF_TOKEN=hf_" + "AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGh")
    )
