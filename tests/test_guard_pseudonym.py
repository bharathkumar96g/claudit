import random

from hypothesis import given, settings
from hypothesis import strategies as st

from claudit.detect import scan
from claudit.guard.pseudonym import GUARD_CATEGORIES, Session, pseudonym_for
from claudit.synth import plant

CATS = sorted(GUARD_CATEGORIES)


@settings(max_examples=150, deadline=None)
@given(seed=st.integers(min_value=0, max_value=10**6), cat_i=st.integers(min_value=0, max_value=len(CATS) - 1))
def test_pseudonym_keeps_shape_is_detected_as_same_category_and_differs(seed, cat_i):
    category = CATS[cat_i]
    value, embed = plant(random.Random(seed), category)
    key = b"k" * 32
    fake = pseudonym_for(value, category, key)

    assert fake != value
    assert len(fake) == len(value)
    assert fake.count("\n") == value.count("\n")
    # same rule fires on the pseudonym alone, embedded the same way the real value was
    hits = scan(embed.replace(value, fake))
    assert [m.category for m in hits] == [category], (category, hits)
    assert hits[0].value == fake
    # deterministic under the same key, different under another
    assert pseudonym_for(value, category, key) == fake
    assert pseudonym_for(value, category, b"z" * 32) != fake


def test_connection_string_only_changes_the_password():
    value = "postgresql://app_user:nQrS7RPeMOkIUpkD@db.internal.example.net:5432/prod"
    fake = pseudonym_for(value, "connection_string", b"k" * 32)
    assert fake.startswith("postgresql://app_user:") and fake.endswith("@db.internal.example.net:5432/prod")
    assert fake != value and len(fake) == len(value)


def test_private_key_keeps_header_footer_and_line_structure():
    body = "\n".join("Ab12/+Cd" * 8 for _ in range(4))
    value = "-----BEGIN RSA " + "PRIVATE KEY-----\n" + body + "\n-----END RSA " + "PRIVATE KEY-----"
    fake = pseudonym_for(value, "private_key", b"k" * 32)
    assert fake.splitlines()[0] == value.splitlines()[0] and fake.splitlines()[-1] == value.splitlines()[-1]
    assert [len(line) for line in fake.splitlines()] == [len(line) for line in value.splitlines()]
    assert fake != value


def test_session_masks_text_bidirectionally_and_ignores_non_guard_classes():
    s = Session()
    ghp = "ghp_" + "A1b2C3d4" * 5
    text = f'GITHUB_TOKEN={ghp}\nDB_PASSWORD = "Tr0ub4dor&3xyz!!"\nSSN: 219-09-9999\n'
    masked, matches = s.mask_text(text)
    assert [m.category for m in matches] == ["github_token"]
    assert ghp not in masked and "Tr0ub4dor&3xyz!!" in masked and "219-09-9999" in masked  # only guard classes
    fake = s.real_to_fake[ghp]
    assert masked == text.replace(ghp, fake) and s.fake_to_real[fake] == ghp
    assert s.mask_text(f"again {ghp}")[0] == f"again {fake}"  # same pseudonym within the session
    assert s.masked_by_category == {"github_token": 2}
    s.clear()
    assert not s.fake_to_real and s.key == b"\x00" * 32
