import logging

import stripe
from supabase import Client

from auth import draw_payee_id, get_draw, get_escrow_for_draw, get_job, utc_now_iso
from config import platform_fee_bps

log = logging.getLogger(__name__)

ESCROW_PENDING = "pending"
ESCROW_HELD = "held"
ESCROW_RELEASED = "released"
ESCROW_REFUNDED = "refunded"
ESCROW_FAILED = "failed"

ALLOWED_ESCROW_TRANSITIONS = {
    ESCROW_PENDING: {ESCROW_HELD, ESCROW_REFUNDED, ESCROW_FAILED},
    ESCROW_HELD: {ESCROW_RELEASED, ESCROW_REFUNDED},
    ESCROW_RELEASED: set(),
    ESCROW_REFUNDED: set(),
    ESCROW_FAILED: set(),
}


class EscrowError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _assert_transition(current, new_status):
    allowed = ALLOWED_ESCROW_TRANSITIONS.get(current, set())
    if new_status not in allowed:
        raise EscrowError(
            f"Invalid escrow transition from '{current}' to '{new_status}'",
            status_code=409,
        )


def _platform_fee(amount_cents):
    return (amount_cents * platform_fee_bps()) // 10000


def get_profile_stripe_account(supabase: Client, user_id):
    if not user_id:
        return None
    result = (
        supabase.table("profiles")
        .select("stripe_account_id")
        .eq("id", user_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None
    return result.data[0].get("stripe_account_id")


def ensure_escrow_create_allowed(supabase: Client, data, payer_id):
    draw = get_draw(supabase, data["draw_id"])
    if not draw:
        raise EscrowError("Draw not found", status_code=404)
    if str(draw.get("job_id")) != str(data["job_id"]):
        raise EscrowError("draw_id does not belong to job_id", status_code=400)

    job = get_job(supabase, data["job_id"])
    if not job:
        raise EscrowError("Job not found", status_code=404)
    if job.get("owner_id") != payer_id:
        raise EscrowError("Only the job owner can fund escrow", status_code=403)

    payee_id = data.get("payee_id") or draw_payee_id(draw)
    if not payee_id:
        raise EscrowError("payee_id required", status_code=400)
    if draw_payee_id(draw) and draw_payee_id(draw) != payee_id:
        raise EscrowError("payee_id does not match draw assignment", status_code=400)

    existing = get_escrow_for_draw(supabase, data["draw_id"])
    if existing and existing.get("status") not in (ESCROW_REFUNDED, ESCROW_FAILED):
        raise EscrowError("Escrow already exists for this draw", status_code=409)

    amount_cents = int(data["amount_cents"])
    if amount_cents <= 0:
        raise EscrowError("amount_cents must be positive", status_code=400)

    return draw, job, payee_id, amount_cents


def create_escrow_payment(supabase: Client, data, payer_id):
    draw, job, payee_id, amount_cents = ensure_escrow_create_allowed(supabase, data, payer_id)
    idempotency_key = f"escrow-{data['draw_id']}-{amount_cents}"

    intent = stripe.PaymentIntent.create(
        amount=amount_cents,
        currency="usd",
        capture_method="manual",
        metadata={
            "job_id": str(data["job_id"]),
            "draw_id": str(data["draw_id"]),
            "payer_id": str(payer_id),
            "payee_id": str(payee_id),
        },
        idempotency_key=idempotency_key,
    )

    supabase.table("stripe_escrow").insert(
        {
            "job_id": data["job_id"],
            "draw_id": data["draw_id"],
            "payer_id": payer_id,
            "payee_id": payee_id,
            "stripe_payment_intent_id": intent.id,
            "amount_cents": amount_cents,
            "status": ESCROW_PENDING,
        }
    ).execute()

    return {
        "client_secret": intent.client_secret,
        "payment_intent_id": intent.id,
        "draw_id": data["draw_id"],
        "payee_id": payee_id,
    }


def mark_escrow_held(supabase: Client, draw_id):
    escrow = get_escrow_for_draw(supabase, draw_id)
    if not escrow:
        log.warning("Webhook held update skipped; no escrow for draw %s", draw_id)
        return
    current = escrow.get("status")
    if current == ESCROW_HELD:
        return
    _assert_transition(current, ESCROW_HELD)
    supabase.table("stripe_escrow").update(
        {"status": ESCROW_HELD, "held_at": utc_now_iso()}
    ).eq("draw_id", draw_id).eq("status", current).execute()


def release_escrow(supabase: Client, draw_id):
    escrow = get_escrow_for_draw(supabase, draw_id)
    if not escrow:
        raise EscrowError("No escrow record found", status_code=404)

    current = escrow.get("status")
    if current == ESCROW_RELEASED:
        return escrow.get("stripe_transfer_id")

    _assert_transition(current, ESCROW_RELEASED)

    payee_id = escrow.get("payee_id")
    acct_id = get_profile_stripe_account(supabase, payee_id)
    if not acct_id:
        raise EscrowError("Payee has not completed Stripe Connect onboarding", status_code=409)

    intent_id = escrow["stripe_payment_intent_id"]
    amount_cents = int(escrow["amount_cents"])
    transfer_group = f"draw_{draw_id}"

    intent = stripe.PaymentIntent.retrieve(intent_id)
    if intent.status == "requires_capture":
        stripe.PaymentIntent.capture(intent_id, idempotency_key=f"capture-{draw_id}")
    elif intent.status not in ("succeeded", "processing"):
        raise EscrowError(f"PaymentIntent is in state '{intent.status}'", status_code=409)

    fee = _platform_fee(amount_cents)
    transfer_amount = amount_cents - fee
    if transfer_amount <= 0:
        raise EscrowError("Transfer amount must be positive after platform fee", status_code=400)

    transfer = stripe.Transfer.create(
        amount=transfer_amount,
        currency="usd",
        destination=acct_id,
        transfer_group=transfer_group,
        metadata={"draw_id": str(draw_id), "payee_id": str(payee_id)},
        idempotency_key=f"transfer-{draw_id}",
    )

    now = utc_now_iso()
    supabase.table("stripe_escrow").update(
        {
            "status": ESCROW_RELEASED,
            "released_at": now,
            "stripe_transfer_id": transfer.id,
        }
    ).eq("draw_id", draw_id).eq("status", ESCROW_HELD).execute()

    supabase.table("draws").update({"status": "released", "released_at": now}).eq(
        "id", draw_id
    ).execute()

    return transfer.id


def refund_escrow(supabase: Client, draw_id):
    escrow = get_escrow_for_draw(supabase, draw_id)
    if not escrow:
        raise EscrowError("No escrow record found", status_code=404)

    current = escrow.get("status")
    if current == ESCROW_REFUNDED:
        return

    intent_id = escrow["stripe_payment_intent_id"]
    intent = stripe.PaymentIntent.retrieve(intent_id)

    if current == ESCROW_RELEASED or (
        current == ESCROW_HELD and intent.status == "succeeded"
    ):
        stripe.Refund.create(
            payment_intent=intent_id,
            idempotency_key=f"refund-{draw_id}",
        )
    elif current in (ESCROW_PENDING, ESCROW_HELD) and intent.status in (
        "requires_capture",
        "requires_confirmation",
        "requires_action",
    ):
        _assert_transition(current, ESCROW_REFUNDED)
        stripe.PaymentIntent.cancel(intent_id, idempotency_key=f"cancel-{draw_id}")
    else:
        raise EscrowError(f"Escrow status '{current}' cannot be refunded", status_code=409)

    if current != ESCROW_REFUNDED:
        supabase.table("stripe_escrow").update({"status": ESCROW_REFUNDED}).eq(
            "draw_id", draw_id
        ).eq("status", current).execute()
        supabase.table("draws").update({"status": "refunded"}).eq("id", draw_id).execute()
