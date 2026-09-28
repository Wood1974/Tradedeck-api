"""Shield's own identity: tenants, API keys, members, and isolation.

Shield used to borrow TradeDeck's identity. A caller was a Supabase user in
TradeDeck's project, and every Shield table carried a foreign key into
TradeDeck's `jobs` and `profiles`. That arrangement made the product
unsellable to anyone else: a second business could not hold a record without
first existing as a row in somebody else's marketplace. This module is the
replacement, and it knows nothing about marketplaces.

Two credentials, one principal
------------------------------
A business calling the API from its own systems presents an **API key**. A
human signed in to Shield's web client presents a **member session**. Both
resolve to a single `Principal` carrying a `tenant_id`, because every query in
the service scopes on that one value — one resolution path means one place to
get isolation wrong instead of two.

Why SHA-256 is the right hash here, and is not the mistake it resembles
----------------------------------------------------------------------
The parent app hashed *passwords* as `sha256(password + SECRET_KEY)`, which is
a real defect: passwords are low-entropy and guessable, so they need a slow,
salted KDF — bcrypt, scrypt, argon2 — to make offline cracking expensive.

An API key is different in the way that matters. The secret here is 32 bytes
from `secrets.token_urlsafe`, so there is no dictionary to try and no
meaningful offline attack to slow down; brute force is 2^256 regardless of how
fast the hash is. What a fast hash buys is a verification that does not cost
100ms of CPU on every request, which for a credential presented on every call
is the difference between a working service and a denial of service you built
yourself. Stripe and GitHub store API tokens exactly this way.

So: do not "fix" this by swapping in bcrypt. It is a different problem with a
different answer, and the reasoning is written here so the next person does not
have to guess which one they are looking at.

The token layout
----------------
    shld_<public_id>_<secret>

The `shld_` prefix makes a leaked key identifiable on sight — in a log, a
paste, a public repository — which is what lets a secret scanner find it before
somebody else does. The public id makes verification one indexed lookup rather
than a scan of every hash we hold, and it is safe to log.
"""
import hashlib
import hmac
import re
import secrets

PREFIX = "shld"
SECRET_BYTES = 32
PUBLIC_ID_BYTES = 8

# A principal is one of exactly these. Anything else is a bug, not a new case.
KINDS = ("api_key", "member")

# The public id is hex on purpose: `token_urlsafe` can emit an underscore,
# and with `_` as the separator a public id containing one splits wrong —
# silently, and only for some keys. Caught by a test on the first run.
_TOKEN = re.compile(r"^shld_([a-f0-9]{8,64})_([A-Za-z0-9_-]{20,128})$")


class ApiKey:
    """A freshly minted key. The plaintext exists here and nowhere else.

    `token` is shown to the caller once, at creation, and is not recoverable
    afterwards — only `key_hash` is stored. That is the point: a key we could
    recover is a key we could leak.
    """

    __slots__ = ("token", "public_id", "key_hash")

    def __init__(self, token, public_id, key_hash):
        self.token, self.public_id, self.key_hash = token, public_id, key_hash


def new_api_key() -> ApiKey:
    public_id = secrets.token_hex(PUBLIC_ID_BYTES)
    secret = secrets.token_urlsafe(SECRET_BYTES).rstrip("=")
    return ApiKey(f"{PREFIX}_{public_id}_{secret}", public_id, hash_secret(secret))


def parse_key(token):
    """Split a presented token, or return None if it is not one.

    Deliberately strict. A token that "nearly" parses is not a token, and
    guessing at the caller's intent on an authentication path is how a
    malformed credential ends up treated as a valid one.
    """
    if not isinstance(token, str):
        return None
    match = _TOKEN.match(token.strip())
    return (match.group(1), match.group(2)) if match else None


def hash_secret(secret: str) -> str:
    return hashlib.sha256(str(secret).encode()).hexdigest()


def verify_secret(secret, stored_hash) -> bool:
    """Constant-time comparison of a presented secret against a stored hash.

    Returns False rather than raising on a missing or malformed stored hash. A
    crash here would be an availability bug on the authentication path, and an
    authentication path that crashes on some rows and not others tells an
    attacker which public ids exist.
    """
    if not isinstance(stored_hash, str) or len(stored_hash) != 64:
        return False
    return hmac.compare_digest(hash_secret(secret), stored_hash)


class Principal:
    """Who is calling, and — always — which tenant they are.

    There is no such thing here as an authenticated caller without a tenant.
    Every query scopes on `tenant_id`; one that scoped on None would either
    match nothing or match everything depending on the query builder, and one
    of those is a cross-tenant read. So it is refused at construction.
    """

    __slots__ = ("kind", "tenant_id", "actor_id", "role")

    def __init__(self, kind, tenant_id, actor_id, role=None):
        if kind not in KINDS:
            raise ValueError(f"unknown principal kind {kind!r}")
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            raise ValueError("a principal must carry a tenant_id")
        self.kind = kind
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.role = role

    @property
    def is_api_key(self) -> bool:
        return self.kind == "api_key"

    @property
    def is_member(self) -> bool:
        return self.kind == "member"

    def __repr__(self):
        return f"<Principal {self.kind} tenant={self.tenant_id} actor={self.actor_id}>"


def usable_key(row, secret):
    """The single decision point for "may this key act?".

    Every condition that should stop a key lives here rather than being spread
    across call sites: the row must exist, the secret must match, the key must
    not be revoked, and the tenant must not be suspended. A caller that checks
    three of those four has an authentication bypass, so there is one function
    and it checks all of them.
    """
    if not row:
        return None
    if row.get("revoked_at"):
        return None
    if row.get("tenant_status") not in (None, "active"):
        return None
    if not verify_secret(secret, row.get("key_hash")):
        return None
    tenant_id = row.get("tenant_id")
    if not tenant_id:
        return None
    return Principal(kind="api_key", tenant_id=tenant_id, actor_id=row.get("id"))


def usable_member(row):
    """The same, for a signed-in human. One place, all the conditions."""
    if not row:
        return None
    if row.get("disabled_at"):
        return None
    if row.get("tenant_status") not in (None, "active"):
        return None
    tenant_id = row.get("tenant_id")
    if not tenant_id:
        return None
    return Principal(kind="member", tenant_id=tenant_id,
                     actor_id=row.get("id"), role=row.get("role"))


def scope(query, principal):
    """Constrain a query to the caller's tenant. Every read goes through this.

    Raises on anything that is not a Principal rather than returning the query
    untouched — an unscoped query is the entire vulnerability this module
    exists to prevent, and silently producing one is worse than failing.
    """
    if not isinstance(principal, Principal):
        raise TypeError(
            f"scope() needs a Principal, got {type(principal).__name__}; "
            f"an unscoped query would read across tenants")
    return query.eq("tenant_id", principal.tenant_id)
