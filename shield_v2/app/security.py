from __future__ import annotations
import os,time
from collections import defaultdict,deque
from fastapi import Request,HTTPException
_BUCKETS=defaultdict(deque)
def enforce_rate_limit(request:Request):
    limit=int(os.getenv("SHIELD_RATE_LIMIT_PER_MINUTE","120"))
    key=request.client.host if request.client else "unknown"; now=time.time(); q=_BUCKETS[key]
    while q and q[0]<now-60:q.popleft()
    if len(q)>=limit: raise HTTPException(429,"rate_limit_exceeded")
    q.append(now)
