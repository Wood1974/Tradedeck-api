import os
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get('DB_PATH', 'tradedeck.db')

"""
TradeDeck API — Flask backend
Deployed on Render at tradedeck-api.onrender.com
GitHub repo: Wood1974/tradedeck-api

ENV VARS REQUIRED (set in Render dashboard):
  SUPABASE_URL       = https://jlaajejpqjldpbinktln.supabase.co
  SUPABASE_KEY       = your_supabase_service_role_key
  STRIPE_SECRET_KEY  = sk_test_...  (Jkw sandbox)
  STRIPE_WEBHOOK_SECRET = whsec_...
  ANTHROPIC_API_KEY  = sk-ant-...  (platform.claude.com)
  PERPLEXITY_API_KEY = pplx-...    (for job enhance endpoint)
"""

import os, json, hmac, hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
import anthropic
import stripe
from supabase import create_client

app = Flask(__name__)
CORS(app)

# ─── Clients ──────────────────────────────────────────────────────────────
sb = create_client(os.environ['SUPABASE_URL'], os.environ['SUPABASE_KEY'])
stripe.api_key = os.environ['STRIPE_SECRET_KEY']
ant = anthropic.Anthropic(api_key=os.environ['ANTHROPIC_API_KEY'])

# ─── Health ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return jsonify({'status': 'TradeDeck API running', 'version': '3.0'})

# ─── Jobs ─────────────────────────────────────────────────────────────────
@app.route('/api/jobs', methods=['GET'])
def get_jobs():
    county = request.args.get('county')
    source = request.args.get('source')
    query = sb.table('jobs').select('*').eq('status', 'open').order('created_at', desc=True).limit(100)
    if county:
        query = query.eq('county', county)
    if source:
        query = query.eq('source', source)
    res = query.execute()
    return jsonify(res.data)

@app.route('/api/jobs', methods=['POST'])
def post_job():
    data = request.json
    required = ['title', 'posted_by']
    for f in required:
        if not data.get(f):
            return jsonify({'error': f'{f} required'}), 400
    data['source'] = data.get('source', 'tradedeck')
    data['status'] = 'open'
    res = sb.table('jobs').insert(data).execute()
    return jsonify(res.data[0] if res.data else {}), 201

@app.route('/api/jobs/<job_id>', methods=['PATCH'])
def update_job(job_id):
    data = request.json
    res = sb.table('jobs').update(data).eq('id', job_id).execute()
    return jsonify(res.data[0] if res.data else {})

# ─── Payments ─────────────────────────────────────────────────────────────
@app.route('/api/payments/intent', methods=['POST'])
def create_payment_intent():
    """
    Creates a $20 Stripe PaymentIntent for any fee-gated action.
    action_type: 'worker_apply' | 'contractor_hire' | 'job_post'
    """
    data = request.json
    amount = data.get('amount', 2000)  # cents, default $20
    action_type = data.get('action_type', 'platform_fee')
    user_id = data.get('user_id', '')
    metadata = data.get('metadata', {})

    try:
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='usd',
            metadata={
                'action_type': action_type,
                'user_id': user_id,
                **{k: str(v) for k, v in metadata.items()}
            },
            description=f'TradeDeck platform fee — {action_type}'
        )
        return jsonify({'client_secret': intent.client_secret})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── Job Enhance (Perplexity → Claude) ───────────────────────────────────
@app.route('/api/jobs/enhance', methods=['POST'])
def enhance_job():
    """
    Takes raw job fields, sends to Claude via Perplexity Gateway,
    returns a cleaned title + professional description.
    """
    data = request.json
    raw = f"Title: {data.get('title','')}\nTrade: {data.get('trade_type','')}\nDetails: {data.get('description','')}\nLocation: {data.get('location','')}\nBudget: {data.get('budget','')}"

    perplexity_client = anthropic.Anthropic(
        api_key=os.environ.get('PERPLEXITY_API_KEY',''),
        base_url='https://api.perplexity.ai/router'
    )
    msg = perplexity_client.messages.create(
        model='anthropic/claude-sonnet-4-6',
        max_tokens=500,
        messages=[{
            'role': 'user',
            'content': f'Rewrite this job posting for a contractor marketplace. Return JSON only with keys: title (clean, specific), description (2-3 sentences, professional tone). Raw input:\n{raw}'
        }]
    )
    text = msg.content[0].text if msg.content else '{}'
    try:
        result = json.loads(text.strip().strip('```json').strip('```'))
    except Exception:
        result = {'title': data.get('title',''), 'description': text}
    return jsonify(result)

# ─── Draws / Escrow ───────────────────────────────────────────────────────
@app.route('/api/draws', methods=['GET'])
def get_draws():
    job_id = request.args.get('job_id')
    query = sb.table('draw_schedules').select('*, milestones(*)')
    if job_id:
        query = query.eq('job_id', job_id)
    res = query.execute()
    return jsonify(res.data)

@app.route('/api/draws', methods=['POST'])
def create_draw():
    data = request.json
    res = sb.table('draw_schedules').insert({
        'job_id': data['job_id'],
        'contract_value': data['contract_value']
    }).execute()
    schedule = res.data[0] if res.data else {}
    if data.get('milestones') and schedule.get('id'):
        ms = [{'schedule_id': schedule['id'], 'name': m['name'],
               'pct': m['pct'], 'order_num': i+1,
               'verifier_type': m.get('verifier','owner'), 'status': 'pending'}
              for i, m in enumerate(data['milestones'])]
        sb.table('milestones').insert(ms).execute()
    return jsonify(schedule), 201

@app.route('/api/draws/milestones/<milestone_id>', methods=['PATCH'])
def update_milestone(milestone_id):
    data = request.json
    allowed = ['status']
    update = {k: v for k, v in data.items() if k in allowed}
    res = sb.table('milestones').update(update).eq('id', milestone_id).execute()

    # If approved, create Stripe payout intent
    if update.get('status') == 'approved':
        ms_data = res.data[0] if res.data else {}
        schedule_res = sb.table('draw_schedules').select('*').eq('id', ms_data.get('schedule_id','')).single().execute()
        if schedule_res.data:
            contract_val = schedule_res.data.get('contract_value', 0)
            amount_cents = int(contract_val * (ms_data.get('pct', 0) / 100) * 100)
            if amount_cents > 0:
                try:
                    # Log escrow release event
                    sb.table('draw_events').insert({
                        'milestone_id': milestone_id,
                        'event_type': 'approved',
                        'amount_cents': amount_cents
                    }).execute()
                except Exception:
                    pass

    return jsonify(res.data[0] if res.data else {})

# ─── Photo Quality Check (Anthropic Vision) ───────────────────────────────
@app.route('/api/photos/check', methods=['POST'])
def check_photo():
    """
    Accepts a base64 image, runs Claude vision quality check,
    returns {approved: bool, feedback: str}
    """
    data = request.json
    image_b64 = data.get('image_b64')
    milestone_name = data.get('milestone_name', 'work')
    if not image_b64:
        return jsonify({'error': 'image_b64 required'}), 400
    try:
        msg = ant.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=300,
            messages=[{
                'role': 'user',
                'content': [
                    {
                        'type': 'image',
                        'source': {'type': 'base64', 'media_type': 'image/jpeg', 'data': image_b64}
                    },
                    {
                        'type': 'text',
                        'text': f'This is a construction site progress photo for milestone: "{milestone_name}". Is this a clear, relevant photo showing actual construction work? Reply JSON only: {{"approved": true/false, "feedback": "one sentence"}}'
                    }
                ]
            }]
        )
        text = msg.content[0].text.strip().strip('```json').strip('```')
        result = json.loads(text)
    except Exception as e:
        result = {'approved': True, 'feedback': 'Photo accepted.'}
    return jsonify(result)

# ─── Stripe Webhook ───────────────────────────────────────────────────────
@app.route('/api/stripe/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    sig = request.headers.get('Stripe-Signature','')
    try:
        event = stripe.Webhook.construct_event(payload, sig, os.environ['STRIPE_WEBHOOK_SECRET'])
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    if event['type'] == 'payment_intent.succeeded':
        pi = event['data']['object']
        meta = pi.get('metadata', {})
        if meta.get('milestone_id'):
            sb.table('milestones').update({'status': 'approved'}).eq('id', meta['milestone_id']).execute()

    elif event['type'] == 'account.updated':
        account = event['data']['object']
        if account.get('charges_enabled'):
            sb.table('profiles').update({'stripe_onboarded': True}).eq('stripe_account_id', account['id']).execute()

    return jsonify({'received': True})

# ─── Stripe Connect Onboarding ────────────────────────────────────────────
@app.route('/api/stripe/connect', methods=['POST'])
def stripe_connect():
    data = request.json
    user_id = data.get('user_id')
    email = data.get('email')
    if not user_id or not email:
        return jsonify({'error': 'user_id and email required'}), 400
    try:
        account = stripe.Account.create(type='express', email=email,
            capabilities={'transfers': {'requested': True}})
        sb.table('profiles').update({'stripe_account_id': account.id}).eq('id', user_id).execute()
        link = stripe.AccountLink.create(
            account=account.id,
            refresh_url='https://tradedeckapp.com/profile',
            return_url='https://tradedeckapp.com/profile',
            type='account_onboarding'
        )
        return jsonify({'url': link.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─── KSL Jobs (ingestion endpoint for scraper) ────────────────────────────
@app.route('/api/ksl/ingest', methods=['POST'])
def ksl_ingest():
    """
    Called by the KSL scraper (Mac crontab / launchd).
    Accepts array of job objects, upserts by ksl_job_id.
    """
    jobs = request.json if isinstance(request.json, list) else []
    added = 0
    skipped = 0
    for job in jobs:
        ksl_id = job.get('ksl_job_id')
        if not ksl_id:
            continue
        existing = sb.table('jobs').select('id').eq('ksl_job_id', ksl_id).execute()
        if existing.data:
            skipped += 1
            continue
        sb.table('jobs').insert({
            'title': job.get('title',''),
            'company': job.get('company',''),
            'description': job.get('description',''),
            'location': job.get('location',''),
            'county': job.get('county',''),
            'pay': job.get('pay',''),
            'job_type': job.get('job_type',''),
            'source': 'ksl',
            'ksl_job_id': ksl_id,
            'status': 'open'
        }).execute()
        added += 1
    return jsonify({'added': added, 'skipped': skipped})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
