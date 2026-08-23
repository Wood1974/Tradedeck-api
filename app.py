import os,json,anthropic,stripe
from datetime import datetime
from flask import Flask,request,jsonify
from flask_cors import CORS
from supabase import create_client,Client
 
app=Flask(__name__)
CORS(app)
 
stripe.api_key=os.environ.get("STRIPE_SECRET_KEY","")
STRIPE_WEBHOOK_SECRET=os.environ.get("STRIPE_WEBHOOK_SECRET","")
SUPABASE_URL=os.environ.get("SUPABASE_URL","")
SUPABASE_SERVICE_KEY=os.environ.get("SUPABASE_SERVICE_KEY","")
supabase=create_client(SUPABASE_URL,SUPABASE_SERVICE_KEY)
anthropic_client=anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY",""))
 
@app.route("/")
def index():
    return jsonify({"status":"TradeDeck API running","version":"2.0"})
 
@app.route("/api/jobs",methods=["GET"])
def get_jobs():
    trade=request.args.get("trade","")
    location=request.args.get("location","")
    status=request.args.get("status","open")
    q=supabase.table("jobs").select("*").eq("status",status)
    if trade: q=q.eq("trade",trade)
    if location: q=q.ilike("location",f"%{location}%")
    r=q.order("created_at",desc=True).execute()
    return jsonify({"jobs":r.data,"count":len(r.data)})
 
@app.route("/api/jobs",methods=["POST"])
def post_job():
    data=request.get_json(silent=True) or {}
    missing=[f for f in ["title","trade","location","owner_id"] if not data.get(f)]
    if missing: return jsonify({"error":"Missing: "+", ".join(missing)}),400
    r=supabase.table("jobs").insert({"owner_id":data["owner_id"],"title":data["title"],"trade":data["trade"],"location":data["location"],"description":data.get("description",""),"budget":data.get("budget"),"status":"open"}).execute()
    return jsonify({"success":True,"job":r.data[0]}),201
 
@app.route("/stripe/connect/onboard",methods=["POST"])
def stripe_connect_onboard():
    data=request.get_json(silent=True) or {}
    user_id=data.get("user_id")
    if not user_id: return jsonify({"error":"user_id required"}),400
    try:
        acct=stripe.Account.create(type="express",email=data.get("email"),capabilities={"transfers":{"requested":True}})
        supabase.table("profiles").update({"stripe_account_id":acct.id}).eq("id",user_id).execute()
        base_url=os.environ.get("APP_URL","https://tradedeckapp.com")
        link=stripe.AccountLink.create(account=acct.id,refresh_url=base_url+"/profile",return_url=base_url+"/profile?stripe=success",type="account_onboarding")
        return jsonify({"url":link.url,"account_id":acct.id})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/stripe/escrow/create",methods=["POST"])
def escrow_create():
    data=request.get_json(silent=True) or {}
    missing=[f for f in ["job_id","draw_id","amount_cents","payer_id"] if not data.get(f)]
    if missing: return jsonify({"error":"Missing: "+", ".join(missing)}),400
    try:
        intent=stripe.PaymentIntent.create(amount=int(data["amount_cents"]),currency="usd",capture_method="manual",metadata={"job_id":str(data["job_id"]),"draw_id":str(data["draw_id"])})
        supabase.table("stripe_escrow").insert({"job_id":data["job_id"],"draw_id":data["draw_id"],"payer_id":data["payer_id"],"payee_id":data.get("payee_id"),"stripe_payment_intent_id":intent.id,"amount_cents":int(data["amount_cents"]),"status":"pending"}).execute()
        return jsonify({"client_secret":intent.client_secret,"payment_intent_id":intent.id})
    except Exception as e: return jsonify({"error":str(e)}),500
 
def _release(draw_id):
    er=supabase.table("stripe_escrow").select("*").eq("draw_id",draw_id).execute()
    if not er.data: return None,"No escrow record found"
    escrow=er.data[0]
    intent_id=escrow["stripe_payment_intent_id"]
    payee_id=escrow.get("payee_id")
    amount_cents=escrow["amount_cents"]
    acct_id=None
    if payee_id:
        pr=supabase.table("profiles").select("stripe_account_id").eq("id",payee_id).execute()
        if pr.data: acct_id=pr.data[0].get("stripe_account_id")
    stripe.PaymentIntent.capture(intent_id)
    transfer_id=None
    if acct_id:
        fee=int(amount_cents*0.02)
        t=stripe.Transfer.create(amount=amount_cents-fee,currency="usd",destination=acct_id,transfer_group="draw_"+draw_id)
        transfer_id=t.id
    now=datetime.utcnow().isoformat()
    supabase.table("stripe_escrow").update({"status":"released","released_at":now,"stripe_transfer_id":transfer_id}).eq("draw_id",draw_id).execute()
    supabase.table("draws").update({"status":"released","released_at":now}).eq("id",draw_id).execute()
    return transfer_id,None
 
@app.route("/stripe/escrow/release",methods=["POST"])
def escrow_release():
    data=request.get_json(silent=True) or {}
    draw_id=data.get("draw_id")
    if not draw_id: return jsonify({"error":"draw_id required"}),400
    try:
        tid,err=_release(draw_id)
        if err: return jsonify({"error":err}),404
        return jsonify({"success":True,"transfer_id":tid})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/stripe/escrow/refund",methods=["POST"])
def escrow_refund():
    data=request.get_json(silent=True) or {}
    draw_id=data.get("draw_id")
    if not draw_id: return jsonify({"error":"draw_id required"}),400
    try:
        r=supabase.table("stripe_escrow").select("*").eq("draw_id",draw_id).execute()
        if not r.data: return jsonify({"error":"No escrow record"}),404
        stripe.PaymentIntent.cancel(r.data[0]["stripe_payment_intent_id"])
        supabase.table("stripe_escrow").update({"status":"refunded"}).eq("draw_id",draw_id).execute()
        supabase.table("draws").update({"status":"disputed"}).eq("id",draw_id).execute()
        return jsonify({"success":True})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/draws/<draw_id>",methods=["GET"])
def get_draw(draw_id):
    try:
        d=supabase.table("draws").select("*").eq("id",draw_id).execute()
        e=supabase.table("stripe_escrow").select("*").eq("draw_id",draw_id).execute()
        p=supabase.table("draw_photos").select("*").eq("draw_id",draw_id).execute()
        return jsonify({"draw":d.data[0] if d.data else None,"escrow":e.data[0] if e.data else None,"photos":p.data})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/draws/<draw_id>/approve",methods=["POST"])
def approve_draw(draw_id):
    try:
        supabase.table("draws").update({"status":"owner_approved","approved_at":datetime.utcnow().isoformat()}).eq("id",draw_id).execute()
        tid,err=_release(draw_id)
        if err: return jsonify({"error":err}),404
        return jsonify({"success":True,"transfer_id":tid})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/draws/<draw_id>/photos/upload",methods=["POST"])
def upload_photo(draw_id):
    data=request.get_json(silent=True) or {}
    uploaded_by=data.get("uploaded_by")
    image_b64=data.get("image_base64")
    storage_path=data.get("storage_path","draws/"+draw_id+"/"+str(datetime.utcnow().timestamp())+".jpg")
    if not image_b64: return jsonify({"error":"image_base64 required"}),400
    try:
        prompt='You are a construction quality inspector reviewing a milestone photo for payment release. Respond ONLY with valid JSON: {"score":<0-100>,"passed":<true|false>,"summary":"<one sentence>","flags":[],"recommendations":[]} Score 80+ = passed. Be strict.'
        msg=anthropic_client.messages.create(model="claude-sonnet-4-6",max_tokens=1024,messages=[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/jpeg","data":image_b64}},{"type":"text","text":prompt}]}])
        raw=msg.content[0].text.strip()
        if raw.startswith("```"):
            raw=raw.split("```")[1]
            if raw.startswith("json"): raw=raw[4:]
        ai=json.loads(raw.strip())
        score=ai.get("score",0)
        passed=ai.get("passed",False)
        flags=ai.get("flags",[])
        pr=supabase.table("draw_photos").insert({"draw_id":draw_id,"uploaded_by":uploaded_by,"storage_path":storage_path,"ai_analysis":ai,"ai_passed":passed,"ai_score":score,"ai_summary":ai.get("summary",""),"ai_flags":flags}).execute()
        supabase.table("draws").update({"status":"ai_approved" if passed else "ai_flagged","submitted_at":datetime.utcnow().isoformat()}).eq("id",draw_id).execute()
        return jsonify({"success":True,"photo_id":pr.data[0]["id"],"ai_score":score,"ai_passed":passed,"ai_summary":ai.get("summary",""),"ai_flags":flags,"ai_recommendations":ai.get("recommendations",[])})
    except json.JSONDecodeError: return jsonify({"error":"AI returned invalid JSON"}),500
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/draws/<draw_id>/photos",methods=["GET"])
def get_photos(draw_id):
    try:
        p=supabase.table("draw_photos").select("*").eq("draw_id",draw_id).execute()
        return jsonify({"photos":p.data})
    except Exception as e: return jsonify({"error":str(e)}),500
 
@app.route("/stripe/webhook",methods=["POST"])
def stripe_webhook():
    try:
        event=stripe.Webhook.construct_event(request.data,request.headers.get("Stripe-Signature",""),STRIPE_WEBHOOK_SECRET)
    except Exception as e: return jsonify({"error":str(e)}),400
    if event["type"]=="payment_intent.amount_capturable_updated":
        did=event["data"]["object"]["metadata"].get("draw_id")
        if did: supabase.table("stripe_escrow").update({"status":"held","held_at":datetime.utcnow().isoformat()}).eq("draw_id",did).execute()
    return jsonify({"received":True})
 
if __name__=="__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)
