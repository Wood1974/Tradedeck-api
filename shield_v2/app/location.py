from __future__ import annotations
from datetime import datetime,timezone
from math import radians,sin,cos,sqrt,atan2,isfinite
import os
EARTH_RADIUS_M=6371000.0
def distance_m(a_lat,a_lng,b_lat,b_lng):
    p1,p2=radians(a_lat),radians(b_lat);dp=radians(b_lat-a_lat);dl=radians(b_lng-a_lng);x=sin(dp/2)**2+cos(p1)*cos(p2)*sin(dl/2)**2
    return 2*EARTH_RADIUS_M*atan2(sqrt(x),sqrt(1-x))
def _valid_coords(lat,lng):
    try:lat,lng=float(lat),float(lng);return isfinite(lat) and isfinite(lng) and -90<=lat<=90 and -180<=lng<=180
    except (TypeError,ValueError):return False
def _parse_time(value):
    if not value:return None
    try:
        dt=datetime.fromisoformat(str(value).replace("Z","+00:00"))
        if dt.tzinfo is None:dt=dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError,ValueError):return None
def evaluate_location(*,lat=None,lng=None,accuracy_m=None,observed_at=None,expected_lat=None,expected_lng=None,mock_flag=None,now=None,config=None):
    cfg={"max_age_seconds":int(os.getenv("SHIELD_LOCATION_MAX_AGE_SECONDS","120")),"max_accuracy_m":float(os.getenv("SHIELD_LOCATION_MAX_ACCURACY_M","100")),"consistent_radius_m":float(os.getenv("SHIELD_LOCATION_CONSISTENT_RADIUS_M","200")),"reject_radius_m":float(os.getenv("SHIELD_LOCATION_REJECT_RADIUS_M","2000"))}
    if config:cfg.update(config)
    now=now or datetime.now(timezone.utc);reasons=[];hard=False
    if mock_flag is True:reasons.append("mock_location_flag");hard=True
    if lat is None or lng is None:return {"verdict":"flag","reasons":reasons+["location_missing"],"distance_m":None,"age_seconds":None,"accuracy_m":accuracy_m}
    if not _valid_coords(lat,lng):return {"verdict":"reject","reasons":["invalid_coordinates"],"distance_m":None,"age_seconds":None,"accuracy_m":accuracy_m}
    lat,lng=float(lat),float(lng)
    if accuracy_m is None:reasons.append("accuracy_missing")
    else:
        try:
            accuracy_m=float(accuracy_m)
            if not isfinite(accuracy_m) or accuracy_m<0:return {"verdict":"reject","reasons":["invalid_accuracy"],"distance_m":None,"age_seconds":None,"accuracy_m":accuracy_m}
            if accuracy_m>cfg["max_accuracy_m"]:reasons.append("poor_accuracy")
        except (TypeError,ValueError):return {"verdict":"reject","reasons":["invalid_accuracy"],"distance_m":None,"age_seconds":None,"accuracy_m":accuracy_m}
    fix=_parse_time(observed_at);age=None
    if fix is None:reasons.append("location_time_missing")
    else:
        age=(now-fix).total_seconds()
        if age < -30:reasons.append("location_time_in_future")
        elif age>cfg["max_age_seconds"]:reasons.append("stale_location")
    dist=None
    if expected_lat is None or expected_lng is None:reasons.append("expected_location_missing")
    elif not _valid_coords(expected_lat,expected_lng):reasons.append("expected_location_invalid")
    else:
        dist=distance_m(lat,lng,float(expected_lat),float(expected_lng));unc=max(float(accuracy_m or 0),0)
        if dist>cfg["reject_radius_m"]+unc:reasons.append("outside_reject_radius");hard=True
        elif dist>cfg["consistent_radius_m"]+unc:reasons.append("outside_consistent_radius")
    return {"verdict":"reject" if hard else ("flag" if reasons else "consistent"),"reasons":reasons,"distance_m":dist,"age_seconds":age,"accuracy_m":accuracy_m}
