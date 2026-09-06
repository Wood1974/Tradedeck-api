"""
TRADEDECK SHIELD — shield_api.py (MERGED COMPLETE VERSION)
Add to your tradedeck-api repo alongside app.py.

Register in app.py:
    from shield_api import shield_bp
    app.register_blueprint(shield_bp)

Environment variables required on Render:
    STRIPE_SECRET_KEY
    STRIPE_WEBHOOK_SECRET
    STRIPE_SHIELD_PRICE_ID
    ANTHROPIC_API_KEY
    SUPABASE_URL
    SUPABASE_SERVICE_KEY
"""

import os, json, base64, hashlib, requests
import stripe
import anthropic
from flask import Blueprint, request, jsonify
from datetime import datetime

shield_bp = Blueprint('shield', __name__, url_prefix='/shield')

stripe.api_key         = os.environ.get('STRIPE_SECRET_KEY')
ANTHROPIC_API_KEY      = os.environ.get('ANTHROPIC_API_KEY')
STRIPE_WEBHOOK_SECRET  = os.environ.get('STRIPE_WEBHOOK_SECRET')
STRIPE_SHIELD_PRICE_ID = os.environ.get('STRIPE_SHIELD_PRICE_ID')
SUPABASE_URL           = os.environ.get('SUPABASE_URL')
SUPABASE_SERVICE_KEY   = os.environ.get('SUPABASE_SERVICE_KEY')
ADMIN_EMAIL            = 'woodalljosh128@gmail.com'

# ─────────────────────────────────────────────────
# SUPABASE HELPERS (service role — bypasses RLS)
# ─────────────────────────────────────────────────
def _headers():
    return {
        'apikey': SUPABASE_SERVICE_KEY,
        'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
        'Content-Type': 'application/json',
        'Prefer': 'return=representation'
    }

def supa_insert(table, data):
    r = requests.post(f'{SUPABASE_URL}/rest/v1/{table}', headers=_headers(), json=data)
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else rows

def supa_update(table, match_col, match_val, data):
    r = requests.patch(
        f'{SUPABASE_URL}/rest/v1/{table}?{match_col}=eq.{match_val}',
        headers=_headers(), json=data
    )
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else rows

def supa_select(table, filters: dict):
    params = '&'.join(f'{k}=eq.{v}' for k, v in filters.items())
    r = requests.get(f'{SUPABASE_URL}/rest/v1/{table}?{params}', headers=_headers())
    rows = r.json()
    return rows[0] if isinstance(rows, list) and rows else None

# ─────────────────────────────────────────────────
# JWT VALIDATION
# Verifies the Supabase access token on every request.
# ─────────────────────────────────────────────────
def get_user_from_token():
    """Extract and verify the user from the Bearer token."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ', 1)[1]
    # Verify token against Supabase auth
    r = requests.get(
        f'{SUPABASE_URL}/auth/v1/user',
        headers={
            'apikey': SUPABASE_SERVICE_KEY,
            'Authorization': f'Bearer {token}'
        }
    )
    if r.status_code != 200:
        return None
    return r.json()

def require_auth(f):
    """Decorator — returns 401 if no valid token."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────
# ROUTE 1 — Create PaymentIntent (homeowner per-job)
# POST /shield/create-payment-intent
# ─────────────────────────────────────────────────
@shield_bp.route('/create-payment-intent', methods=['POST'])
@require_auth
def create_payment_intent():
    data         = request.get_json()
    job_id       = data.get('job_id')
    amount_cents = data.get('amount_cents')
    if not job_id or not amount_cents:
        return jsonify({'error': 'job_id and amount_cents required'}), 400

    intent = stripe.PaymentIntent.create(
        amount=int(amount_cents),
        currency='usd',
        metadata={'job_id': job_id, 'product': 'shield_per_job'},
        description=f'TradeDeck Shield — Job {job_id}'
    )
    return jsonify({'client_secret': intent.client_secret})


# ─────────────────────────────────────────────────
# ROUTE 2 — Contractor Stripe Checkout subscription
# POST /shield/contractor-subscribe
# ─────────────────────────────────────────────────
@shield_bp.route('/contractor-subscribe', methods=['POST'])
@require_auth
def contractor_subscribe():
    data          = request.get_json()
    contractor_id = data.get('contractor_id')
    if not contractor_id:
        return jsonify({'error': 'contractor_id required'}), 400

    existing = supa_select('shield_subscriptions', {'contractor_id': contractor_id})
    if existing and existing.get('stripe_customer_id'):
        customer_id = existing['stripe_customer_id']
    else:
        customer    = stripe.Customer.create(metadata={'contractor_id': contractor_id})
        customer_id = customer.id

    checkout = stripe.checkout.Session.create(
        customer=customer_id,
        mode='subscription',
        line_items=[{'price': STRIPE_SHIELD_PRICE_ID, 'quantity': 1}],
        success_url='https://tradedeckapp.com/app.html?shield_sub=success',
        cancel_url='https://tradedeckapp.com/app.html?shield_sub=cancelled',
        metadata={'contractor_id': contractor_id, 'product': 'shield_pro'}
    )
    return jsonify({'stripe_url': checkout.url})


# ─────────────────────────────────────────────────
# ROUTE 3 — AI Photo Analysis (Claude Vision)
# POST /shield/analyze-photo
# ─────────────────────────────────────────────────
@shield_bp.route('/analyze-photo', methods=['POST'])
@require_auth
def analyze_photo():
    data       = request.get_json()
    photo_id   = data.get('photo_id')
    public_url = data.get('public_url')
    point_id   = data.get('point_id')
    gps_lat    = data.get('gps_lat')
    gps_lng    = data.get('gps_lng')
    has_exif       = data.get('has_exif', False)
    code_reference = data.get('code_reference', None)
    if not all([photo_id, public_url, point_id]):
        return jsonify({'error': 'photo_id, public_url, and point_id required'}), 400
    # GPS required — reject if missing
    if gps_lat is None or gps_lng is None:
        return jsonify({'error': 'GPS coordinates required for Shield photo verification'}), 400

    point       = supa_select('shield_pivotal_points', {'id': point_id})
    point_label = point.get('label', 'Checkpoint') if point else 'Checkpoint'
    point_desc  = point.get('description', '') if point else ''

    code_ref_line = code_reference if code_reference else 'Not specified'
    img_r = requests.get(public_url, timeout=15)
    if img_r.status_code != 200:
        return jsonify({'error': 'Could not fetch photo'}), 502

    image_b64    = base64.b64encode(img_r.content).decode('utf-8')
    content_type = img_r.headers.get('content-type', 'image/jpeg').split(';')[0]

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=600,
        system=(
            'You are a licensed building inspector and fraud detection analyst. '
            'You evaluate contractor-submitted photos for homeowner protection. '
            'Your job has TWO parts: (1) verify the photo is authentic and taken on-site, '
            '(2) verify the work meets the checkpoint requirement. '
            'Respond ONLY with a valid JSON object — no preamble, no markdown.'
        ),
        messages=[{
            'role': 'user',
            'content': [
                {
                    'type': 'image',
                    'source': {'type': 'base64', 'media_type': content_type, 'data': image_b64}
                },
                {
                    'type': 'text',
                    'text': f'''Checkpoint: {point_label}
Required condition: {point_desc}

METADATA PROVIDED BY THE APP:
- GPS captured: {f"{gps_lat:.5f}, {gps_lng:.5f}" if gps_lat else "NOT PROVIDED"}
- Code Requirement: {code_ref_line}
- Camera EXIF data present: {"YES" if has_exif else "NO — possible screenshot or downloaded image"}

STEP 1 — AUTHENTICITY CHECK (check ALL of these):
- Is this a real on-site construction photo, or a stock image / screenshot / render / AI image?
- Does it show genuine construction conditions (dust, tools, materials, real lighting, shadows)?
- Are there signs of digital manipulation, compositing, or watermarks from another source?
- Look for: unnatural lighting, impossible shadows, blurred/sharp edges where objects meet, repeated texture patterns, unnatural noise, AI rendering artifacts, or inconsistent image quality across regions?
- Does the image content appear consistent with a real active job site?
- EXIF status: if EXIF is missing, treat this as a strong authenticity concern.
- Screens/monitors in frame: if the photo appears to be of a screen or printed image, mark fake.

STEP 2 — QUALITY CHECK (only if authentic):
- Does the photo show what the checkpoint requires?
- Is the work complete, correct, and up to standard?

Respond with this exact JSON:
{{
  "authentic": true | false,
  "authenticity_note": "<one sentence — why authentic or why suspicious>",
  "verdict": "pass" | "flag" | "fail" | "fake",
  "confidence": <float 0-1>,
  "notes": "<2-3 sentence assessment for the homeowner>"
}}

verdict rules:
- fake  = photo is not authentic (stock image, screenshot, render, photo of screen, manipulated, EXIF absent)
- fail  = authentic but work is incomplete, incorrect, or quality concern visible
- flag  = authentic, mostly correct but worth homeowner attention
- pass  = authentic, GPS confirmed on-site, work complete and up to standard

If verdict is fake, set confidence to 1.0 and notes must explain specifically what gave it away.'''
                }
            ]
        }]
    )

    raw = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
    result     = json.loads(raw)
    authentic  = result.get('authentic', True)
    verdict    = result.get('verdict', 'flag')
    confidence = float(result.get('confidence', 0.7))
    notes      = result.get('notes', '')
    auth_note  = result.get('authenticity_note', '')

    # Force fail if fake — override any other verdict
    if not authentic or verdict == 'fake':
        verdict    = 'fake'
        confidence = 1.0
        notes      = f'⚠️ Photo flagged as inauthentic: {auth_note} This checkpoint has not been verified.'

    # ── Server-side hash of the fetched image bytes ──
    server_hash = hashlib.sha256(img_r.content).hexdigest()

    # ── Get the shield_job_id from the photo record ──
    photo_row  = SUPA.table('shield_photos').select('shield_job_id, contractor_id').eq('id', photo_id).single().execute().data or {}
    s_job_id   = photo_row.get('shield_job_id')
    contractor = photo_row.get('contractor_id')

    supa_update('shield_photos', 'id', photo_id, {
        'ai_verdict':        verdict,
        'ai_confidence':     confidence,
        'ai_notes':          notes,
        'ai_authentic':      authentic,
        'photo_hash':        server_hash,
        'hash_algorithm':    'SHA-256',
        'server_received_at': datetime.now(timezone.utc).isoformat(),
        **(({'code_reference': code_reference}) if code_reference else {}),
    })
    point_status = 'approved' if verdict == 'pass' else 'flagged'
    supa_update('shield_pivotal_points', 'id', point_id, {'status': point_status})

    # ── Log chain-of-custody event ──
    log_custody(
        photo_id    = photo_id,
        shield_job_id = s_job_id,
        event_type  = 'ai_analyzed',
        actor_id    = contractor,
        actor_type  = 'ai',
        event_data  = {
            'verdict':          verdict,
            'confidence':       confidence,
            'authentic':        authentic,
            'authenticity_note': auth_note,
            'server_hash':      server_hash,
            'gps_provided':     gps_lat is not None,
            'exif_present':     has_exif,
        },
        gps_lat = gps_lat,
        gps_lng = gps_lng,
    )
    if verdict == 'flagged' or verdict == 'fake':
        log_custody(
            photo_id=photo_id, shield_job_id=s_job_id,
            event_type='flagged', actor_type='ai',
            event_data={'reason': auth_note or notes}
        )

    return jsonify({'verdict': verdict, 'confidence': confidence, 'notes': notes, 'authentic': authentic})


# ─────────────────────────────────────────────────
# ROUTE 4 — Generate AI Pivotal Points
# POST /shield/generate-points
# Called after local points are inserted — enhances them with Claude
# ─────────────────────────────────────────────────
@shield_bp.route('/generate-points', methods=['POST'])
@require_auth
def generate_points():
    data          = request.get_json()
    shield_job_id = data.get('shield_job_id')
    job_id        = data.get('job_id')
    job_desc      = data.get('job_description', '')
    if not all([shield_job_id, job_id, job_desc]):
        return jsonify({'error': 'shield_job_id, job_id, and job_description required'}), 400

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    msg = client.messages.create(
        model='claude-sonnet-4-6',
        max_tokens=600,
        messages=[{'role': 'user', 'content': f'''You are a senior contractor and building inspector.

Job description: """{job_desc}"""

Identify exactly 5 pivotal checkpoints — the specific moments where a photo proves whether the work was done correctly before it is too late to fix. These are the moments a bad contractor would most want to skip.

Return ONLY a valid JSON array, no markdown:
[
  {{"point_number": 1, "label": "<short name>", "description": "<one sentence: exactly what the photo must show>"}},
  ...
]'''}]
    )

    raw    = msg.content[0].text.strip().replace('```json','').replace('```','').strip()
    points = json.loads(raw)

    # Upsert — update the local points already inserted by the frontend
    for p in points:
        existing = requests.get(
            f'{SUPABASE_URL}/rest/v1/shield_pivotal_points?shield_job_id=eq.{shield_job_id}&point_number=eq.{p["point_number"]}',
            headers=_headers()
        ).json()

        if existing:
            supa_update('shield_pivotal_points', 'id', existing[0]['id'], {
                'label': p['label'], 'description': p['description']
            })
        else:
            supa_insert('shield_pivotal_points', {
                'shield_job_id': shield_job_id,
                'job_id':        job_id,
                'point_number':  p['point_number'],
                'label':         p['label'],
                'description':   p['description']
            })

    return jsonify({'points': points})


# ─────────────────────────────────────────────────
# ROUTE 5 — Complete Job (close-out)
# POST /shield/complete-job
# Receives the SHA-256 completion packet from the frontend,
# stores it, freezes the shield_job row, emails admin
# ─────────────────────────────────────────────────
@shield_bp.route('/complete-job', methods=['POST'])
@require_auth
def complete_job():
    packet = request.get_json()
    shield_job_id = packet.get('shield_job_id')
    if not shield_job_id:
        return jsonify({'error': 'shield_job_id required'}), 400

    # Verify the SHA-256 hash matches the packet contents
    submitted_hash = packet.pop('sha256', None)
    packet_string  = json.dumps({k: packet[k] for k in sorted(packet.keys())}, sort_keys=True, separators=(',', ':'))
    expected_hash  = hashlib.sha256(packet_string.encode()).hexdigest()

    # Store the completion record
    supa_insert('shield_completion_reports', {
        'shield_job_id':    shield_job_id,
        'job_id':           packet.get('job_id'),
        'contractor_id':    packet.get('closed_by'),   # whoever closed it
        'homeowner_id':     packet.get('homeowner_id'),
        'overall_verdict':  _derive_verdict(packet.get('points', [])),
        'completion_score': _derive_score(packet.get('points', [])),
        'report_json':      json.dumps({**packet, 'sha256': submitted_hash}),
    })

    # Freeze the shield_job row
    supa_update('shield_jobs', 'id', shield_job_id, {
        'status':       'complete',
        'completed_at': datetime.utcnow().isoformat()
    })

    # Email admin
    _send_completion_email(packet, submitted_hash)

    return jsonify({'ok': True, 'sha256': submitted_hash})


def _derive_verdict(points):
    verdicts = [p.get('photo', {}).get('ai_verdict') for p in points if p.get('photo')]
    if not verdicts:             return 'flag'
    if 'fail' in verdicts:       return 'fail'
    if 'flag' in verdicts:       return 'flag'
    return 'pass'

def _derive_score(points):
    if not points: return 0.0
    scores = {'pass': 100, 'flag': 60, 'fail': 0}
    total  = sum(scores.get(p.get('photo', {}).get('ai_verdict', 'flag'), 60) for p in points)
    return round(total / len(points), 1)

def _send_completion_email(packet, sha256):
    """Send completion record to admin email via Supabase Edge Function or SMTP."""
    try:
        r = requests.post(
            f'{SUPABASE_URL}/functions/v1/send-email',
            headers={
                'apikey': SUPABASE_SERVICE_KEY,
                'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'to':      ADMIN_EMAIL,
                'subject': f'TradeDeck Shield Completion — Job {str(packet.get("job_id",""))[-6:].upper()}',
                'html': f'''
<h2>🛡️ TradeDeck Shield — Job Complete</h2>
<p><strong>Job ID:</strong> {packet.get("job_id")}</p>
<p><strong>Shield Job ID:</strong> {packet.get("shield_job_id")}</p>
<p><strong>Closed at:</strong> {packet.get("closed_at")}</p>
<p><strong>SHA-256:</strong> <code>{sha256}</code></p>
<h3>Checkpoint Summary</h3>
<table border="1" cellpadding="6" style="border-collapse:collapse">
  <tr><th>#</th><th>Label</th><th>AI Verdict</th><th>Confidence</th></tr>
  {"".join(f'''<tr>
    <td>{p["point_number"]}</td>
    <td>{p["label"]}</td>
    <td>{p.get("photo", {}).get("ai_verdict", "NO PHOTO") if p.get("photo") else "NO PHOTO"}</td>
    <td>{str(round(p.get("photo", {}).get("ai_confidence", 0) * 100)) + "%" if p.get("photo") else "—"}</td>
  </tr>''' for p in packet.get("points", []))}
</table>
''',
            },
            timeout=10
        )
        return r.status_code == 200
    except Exception as e:
        print(f'Shield: completion email failed — {e}')
        return False


# ─────────────────────────────────────────────────
# ROUTE 6 — Stripe Webhook
# POST /shield/webhook
# ─────────────────────────────────────────────────
@shield_bp.route('/webhook', methods=['POST'])
def shield_stripe_webhook():
    payload    = request.data
    sig_header = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    obj      = event['data']['object']
    evt_type = event['type']

    if evt_type == 'customer.subscription.created':
        contractor_id = obj.get('metadata', {}).get('contractor_id')
        if contractor_id:
            supa_insert('shield_subscriptions', {
                'contractor_id':      contractor_id,
                'stripe_customer_id': obj['customer'],
                'stripe_sub_id':      obj['id'],
                'status':             'active',
                'current_period_end': obj.get('current_period_end')
            })

    elif evt_type == 'customer.subscription.updated':
        supa_update('shield_subscriptions', 'stripe_sub_id', obj['id'], {
            'status':             obj['status'],
            'current_period_end': obj.get('current_period_end')
        })

    elif evt_type in ('customer.subscription.deleted', 'customer.subscription.paused'):
        supa_update('shield_subscriptions', 'stripe_sub_id', obj['id'], {'status': 'cancelled'})

    elif evt_type == 'payment_intent.succeeded':
        job_id = obj.get('metadata', {}).get('job_id')
        if job_id and obj.get('metadata', {}).get('product') == 'shield_per_job':
            supa_update('shield_jobs', 'job_id', job_id, {'stripe_payment_id': obj['id']})

    return jsonify({'received': True})
