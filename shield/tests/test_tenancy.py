"""Shield's own identity layer, and the isolation it has to guarantee.

Why this exists
---------------
Until now Shield borrowed TradeDeck's identity: a caller was a Supabase user in
TradeDeck's project, and every Shield table carried a foreign key into
TradeDeck's `jobs` and `profiles`. That made Shield unsellable to anyone else —
a second business could not hold a record without first existing as a row in
somebody else's marketplace.

So Shield now has tenants of its own, and two ways to prove you are one:

* an **API key**, for a business calling the API from its own systems
* a **member session**, for a human signed in to Shield's own web client

Both resolve to the same thing — a `Principal` carrying a `tenant_id` — because
every query in the service scopes on that one value. One resolution path means
one place to get isolation wrong, rather than two.

The property that matters more than any other
---------------------------------------------
**A tenant must never be able to read or touch another tenant's records.** Not
by guessing an id, not by presenting a valid credential from a different
tenant, not through a revoked key that used to work. For an evidence product
this is not a normal multi-tenancy concern: the records are contested
documents, and the party most motivated to read them is the one on the other
side of the dispute.

Most of this file is about that.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import tenancy  # noqa: E402


class TestKeyFormat:
    def test_a_new_key_is_prefixed_and_splits_into_two_parts(self):
        """`shld_<public>_<secret>`.

        The prefix makes a leaked key identifiable on sight — in a log, a
        paste, a public repository — which is what lets a secret scanner find
        it before somebody else does. The public half means verification is a
        single indexed lookup rather than a scan of every hash we hold.
        """
        key = tenancy.new_api_key()
        assert key.token.startswith("shld_")
        public_id, secret = tenancy.parse_key(key.token)
        assert public_id == key.public_id
        assert secret and secret != public_id

    def test_the_secret_half_carries_real_entropy(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        # 32 bytes, urlsafe-base64 encoded, unpadded.
        assert len(secret) >= 43

    def test_keys_do_not_repeat(self):
        tokens = {tenancy.new_api_key().token for _ in range(200)}
        assert len(tokens) == 200

    @pytest.mark.parametrize("junk", [
        "", "   ", "shld_", "shld_only-one-part", "wrong_public_secret",
        "shld__emptypublic", "shld_public_", "Bearer shld_a_b",
        None, 12345, "shld_a_b_c_d",
    ])
    def test_malformed_keys_are_rejected_rather_than_parsed(self, junk):
        assert tenancy.parse_key(junk) is None


class TestHashing:
    def test_the_plaintext_secret_is_never_what_we_store(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        assert secret not in key.key_hash
        assert key.token not in key.key_hash

    def test_the_same_secret_hashes_the_same_way(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        assert tenancy.hash_secret(secret) == key.key_hash

    def test_verification_accepts_the_real_secret_and_nothing_else(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        assert tenancy.verify_secret(secret, key.key_hash) is True
        assert tenancy.verify_secret(secret + "x", key.key_hash) is False
        assert tenancy.verify_secret(secret[:-1], key.key_hash) is False
        assert tenancy.verify_secret("", key.key_hash) is False

    def test_verification_survives_a_missing_or_malformed_stored_hash(self):
        """A row with a null hash must fail, not raise.

        A 500 here is an availability bug on the authentication path, and an
        authentication path that crashes is one an attacker can use to tell
        valid public ids from invalid ones.
        """
        for stored in (None, "", "not-a-hash", 12345):
            assert tenancy.verify_secret("anything", stored) is False


class TestPrincipals:
    def test_an_api_key_principal_carries_its_tenant(self):
        p = tenancy.Principal(kind="api_key", tenant_id="t1", actor_id="k1")
        assert p.tenant_id == "t1"
        assert p.is_api_key is True
        assert p.is_member is False

    def test_a_member_principal_carries_its_tenant_and_role(self):
        p = tenancy.Principal(kind="member", tenant_id="t1", actor_id="m1",
                              role="owner")
        assert p.is_member is True
        assert p.role == "owner"

    def test_a_principal_without_a_tenant_cannot_be_built(self):
        """There is no such thing as an authenticated caller with no tenant.

        Every query in the service scopes on tenant_id. A principal that
        carried None would scope on None and, depending on the query builder,
        either match nothing or match everything — and one of those is a
        cross-tenant read.
        """
        for bad in (None, "", "   "):
            with pytest.raises(ValueError):
                tenancy.Principal(kind="api_key", tenant_id=bad, actor_id="k1")

    def test_an_unknown_principal_kind_is_refused(self):
        with pytest.raises(ValueError):
            tenancy.Principal(kind="wat", tenant_id="t1", actor_id="x")


class TestKeyRecordsResolveOnlyWhenUsable:
    """`usable_key` is the single decision point for 'may this key act?'"""

    def make(self, **over):
        row = {"id": "k1", "tenant_id": "t1", "public_id": "pub",
               "key_hash": None, "revoked_at": None,
               "tenant_status": "active"}
        row.update(over)
        return row

    def test_a_live_key_with_the_right_secret_resolves(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        row = self.make(key_hash=key.key_hash)
        principal = tenancy.usable_key(row, secret)
        assert principal is not None
        assert principal.tenant_id == "t1"

    def test_a_revoked_key_never_resolves(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        row = self.make(key_hash=key.key_hash, revoked_at="2026-09-19T00:00:00Z")
        assert tenancy.usable_key(row, secret) is None

    def test_a_key_belonging_to_a_suspended_tenant_never_resolves(self):
        key = tenancy.new_api_key()
        _, secret = tenancy.parse_key(key.token)
        row = self.make(key_hash=key.key_hash, tenant_status="suspended")
        assert tenancy.usable_key(row, secret) is None

    def test_the_wrong_secret_never_resolves(self):
        key = tenancy.new_api_key()
        other = tenancy.new_api_key()
        _, wrong = tenancy.parse_key(other.token)
        row = self.make(key_hash=key.key_hash)
        assert tenancy.usable_key(row, wrong) is None

    def test_a_missing_row_resolves_to_nothing(self):
        assert tenancy.usable_key(None, "secret") is None


class TestIsolation:
    """The property the whole design exists to hold.

    These are unit-level: they check the helper every query is required to go
    through. The database-level half is RLS plus an invariant that no Shield
    table references anything outside its own schema.
    """

    def test_a_query_is_always_scoped_to_the_callers_tenant(self):
        seen = {}

        class FakeQuery:
            def eq(self, column, value):
                seen[column] = value
                return self

        p = tenancy.Principal(kind="api_key", tenant_id="t1", actor_id="k1")
        tenancy.scope(FakeQuery(), p)
        assert seen == {"tenant_id": "t1"}

    def test_scoping_refuses_a_principal_that_is_not_one(self):
        """Passing None here would silently produce an unscoped query.

        That is the whole vulnerability in one line, so it raises rather than
        returning the query untouched.
        """
        class FakeQuery:
            def eq(self, *_):
                raise AssertionError("must not be reached")

        for bad in (None, "t1", {"tenant_id": "t1"}):
            with pytest.raises((TypeError, ValueError)):
                tenancy.scope(FakeQuery(), bad)

    def test_two_tenants_scope_to_different_values(self):
        calls = []

        class FakeQuery:
            def eq(self, column, value):
                calls.append((column, value))
                return self

        a = tenancy.Principal(kind="api_key", tenant_id="tenant-a", actor_id="k")
        b = tenancy.Principal(kind="member", tenant_id="tenant-b", actor_id="m")
        tenancy.scope(FakeQuery(), a)
        tenancy.scope(FakeQuery(), b)
        assert calls == [("tenant_id", "tenant-a"), ("tenant_id", "tenant-b")]


def code_only(module) -> str:
    """Module source with docstrings and comments removed.

    Written because the first version of the test below read raw source and
    failed on `tenancy.py`'s own docstring, which explains the TradeDeck
    coupling in order to say it is gone. That is the third time in this
    codebase a check has fired on prose describing the thing rather than the
    thing — `webapp-sends-no-evidence` did it, and five invariants needed
    rewriting to read the AST for the same reason.

    A check that cannot tell an explanation from an occurrence is not reading
    the code.
    """
    import ast
    import inspect

    source = inspect.getsource(module)
    tree = ast.parse(source)
    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            for i in range(first.lineno - 1, first.end_lineno):
                lines[i] = ""

    return "\n".join(line.split("#")[0] for line in lines).lower()


class TestNoTradeDeckIdentityRemains:
    def test_the_module_knows_nothing_about_profiles_or_jobs(self):
        """Separation, asserted against the code rather than the commentary.

        Shield's callers are tenants and their members. If a TradeDeck concept
        reappears in executable code here — a homeowner, a contractor, a
        profile — the separation has started to leak back. The module is
        allowed to *describe* what it replaced; it is not allowed to use it.
        """
        src = code_only(tenancy)
        for term in ("homeowner", "contractor", "profiles", "tradedeck"):
            assert term not in src, f"tenancy.py uses {term!r} in code"

    def test_the_stripper_itself_works(self):
        """Otherwise the test above passes by removing everything."""
        src = code_only(tenancy)
        assert "def new_api_key" in src
        assert "compare_digest" in src
        assert "unsellable" not in src          # docstring prose, removed


class TestVerificationIsConstantTime:
    def test_a_wrong_secret_does_not_return_faster_the_earlier_it_differs(self):
        """Weak evidence by nature, so it is asserted loosely.

        The real guarantee is that `verify_secret` uses `hmac.compare_digest`,
        which the source is checked for. This only catches a replacement that
        obviously short-circuits — a plain `==` on a long string.
        """
        import inspect
        assert "compare_digest" in inspect.getsource(tenancy.verify_secret)

        key = tenancy.new_api_key()
        early = "a" + "x" * 42
        late = tenancy.parse_key(key.token)[1][:-1] + "x"

        def elapsed(candidate):
            start = time.perf_counter()
            for _ in range(300):
                tenancy.verify_secret(candidate, key.key_hash)
            return time.perf_counter() - start

        ratio = elapsed(early) / max(elapsed(late), 1e-9)
        assert 0.2 < ratio < 5.0
