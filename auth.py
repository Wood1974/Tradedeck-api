
import functools
import logging
from datetime import datetime, timezone
from flask import g, jsonify, request
from supabase import Client
 
log = logging.getLogger(__name__)
 
 
def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()
 
 
def _unauthorized(message="Authentication required"):
    return jsonify({"error": message}), 401
 
 
def _forbidden(message="Forbidden"):
    return jsonify({"error": message}), 403
 
 
def _not_found(message="Not found"):
    return jsonify({"error": message}), 404
 
 
def require_auth(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _unauthorized("Missing or invalid Authorization header")
        token = auth_header[7:].strip()
        if not token:
            return _unauthorized("Missing bearer token")
        supabase: Client = g.supabase
        try:
            user_response = supabase.auth.get_user(token)
        except Exception:
            log.warning("Token verification failed", exc_info=True)
            return _unauthorized("Invalid or expired token")
        user = getattr(user_response, "user", None)
        if not user or not getattr(user, "id", None):
            return _unauthorized("Invalid or expired token")
        g.access_token = token
        g.user = user
        g.user_id = user.id
        return fn(*args, **kwargs)
    return wrapper
 
 
def get_job(supabase: Client, job_id):
    if not job_id:
        return None
    result = supabase.table("jobs").select("*").eq("id", job_id).limit(1).execute()
    if not result.data:
        return None
    return result.data[0]
 
 
def get_draw(supabase: Client, draw_id):
    result = supabase.table("draws").select("*").eq("id", draw_id).limit(1).execute()
    if not result.data:
        return None
    return result.data[0]
 
 
def get_escrow_for_draw(supabase: Client, draw_id):
    result = (
        supabase.table("stripe_escrow")
        .select("*")
        .eq("draw_id", draw_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None
    return result.data[0]
 
 
# IMPORTANT: draws.job_id does NOT reference jobs.id. In the live database
# it is a foreign key to draw_schedules.id -- draw_schedules is the layer
# that sits between a job and its draws, and it already carries its own
# owner_id. So "who owns this draw" is checked against the schedule
# directly, never by treating draws.job_id as if it were a jobs id.
def get_draw_schedule(supabase: Client, schedule_id):
    if not schedule_id:
        return None
    result = (
        supabase.table("draw_schedules")
        .select("*")
        .eq("id", schedule_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None
    return result.data[0]
 
 
def is_job_owner(job, user_id):
    return bool(job) and job.get("owner_id") == user_id
 
 
def is_schedule_owner(schedule, user_id):
    return bool(schedule) and schedule.get("owner_id") == user_id
 
 
# TODO (product decision pending): draws has no payee_id / contractor_id
# column today, so this always returns None and require_draw_payee()
# below will deny every contractor until that's resolved. See the
# accompanying note about where the hired contractor should be recorded.
def draw_payee_id(draw):
    return draw.get("payee_id") or draw.get("contractor_id")
 
 
def is_draw_participant(draw, escrow, user_id):
    if not draw:
        return False
    schedule = get_draw_schedule(g.supabase, draw.get("job_id"))
    if is_schedule_owner(schedule, user_id):
        return True
    if draw_payee_id(draw) == user_id:
        return True
    if escrow and escrow.get("payer_id") == user_id:
        return True
    if escrow and escrow.get("payee_id") == user_id:
        return True
    return False
 
 
def require_job_owner(job_id_param="job_id"):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            job_id = kwargs.get(job_id_param) or (request.get_json(silent=True) or {}).get(job_id_param)
            if not job_id:
                return jsonify({"error": f"{job_id_param} required"}), 400
            job = get_job(g.supabase, job_id)
            if not job:
                return _not_found("Job not found")
            if not is_job_owner(job, g.user_id):
                return _forbidden("Only the job owner can perform this action")
            g.job = job
            return fn(*args, **kwargs)
        return wrapper
    return decorator
 
 
def require_draw_access(draw_id_kw="draw_id"):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            draw_id = kwargs.get(draw_id_kw)
            if not draw_id:
                return jsonify({"error": "draw_id required"}), 400
            draw = get_draw(g.supabase, draw_id)
            if not draw:
                return _not_found("Draw not found")
            escrow = get_escrow_for_draw(g.supabase, draw_id)
            if not is_draw_participant(draw, escrow, g.user_id):
                return _forbidden("You do not have access to this draw")
            g.draw = draw
            g.escrow = escrow
            return fn(*args, **kwargs)
        return wrapper
    return decorator
 
 
def require_draw_owner(draw_id_kw="draw_id"):
    def decorator(fn):
        @require_draw_access(draw_id_kw=draw_id_kw)
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            schedule = get_draw_schedule(g.supabase, g.draw.get("job_id"))
            if not is_schedule_owner(schedule, g.user_id):
                return _forbidden("Only the job owner can perform this action")
            g.schedule = schedule
            return fn(*args, **kwargs)
        return wrapper
    return decorator
 
 
def require_draw_payee(draw_id_kw="draw_id"):
    def decorator(fn):
        @require_draw_access(draw_id_kw=draw_id_kw)
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if draw_payee_id(g.draw) != g.user_id:
                return _forbidden("Only the assigned payee can perform this action")
            return fn(*args, **kwargs)
        return wrapper
    return decorator
