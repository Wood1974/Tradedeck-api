"""
Shield location scoring — deterministic GPS spoofing detection.

Detects GPS spoofing through:
- Impossible speeds (> 250 mph) → reject
- Unrealistic speeds (> 120 mph) or clock skew → flag
- Normal movement pattern → consistent

All computation is deterministic and reproducible.
"""

import math


def _haversine_distance_km(lat1, lon1, lat2, lon2):
    """
    Calculate distance between two GPS points using Haversine formula.

    Returns distance in kilometers.

    Formula:
    distance = 2 * R * arcsin(sqrt(sin²((lat2-lat1)/2) + cos(lat1)*cos(lat2)*sin²((lon2-lon1)/2)))
    where R = 6371 km (Earth radius)
    """
    R = 6371  # Earth radius in kilometers

    # Convert degrees to radians
    lat1_rad = math.radians(lat1)
    lon1_rad = math.radians(lon1)
    lat2_rad = math.radians(lat2)
    lon2_rad = math.radians(lon2)

    # Haversine formula
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    distance_km = R * c
    return distance_km


def _calculate_speed_mph(distance_km, time_delta_seconds):
    """
    Calculate speed in mph from distance and time.

    Args:
        distance_km: distance in kilometers
        time_delta_seconds: time elapsed in seconds

    Returns:
        speed in mph, or infinity if time_delta is 0
    """
    if time_delta_seconds == 0:
        return float('inf')

    # Convert km to miles (1 km = 0.621371 miles)
    distance_miles = distance_km * 0.621371

    # Convert seconds to hours
    time_hours = time_delta_seconds / 3600

    # Speed = distance / time
    speed_mph = distance_miles / time_hours
    return speed_mph


def score(points):
    """
    Score GPS points for spoofing indicators.

    Args:
        points: list of {"lat": float, "lon": float, "timestamp": int}
                timestamp is Unix epoch in seconds

    Returns:
        dict with:
        - "verdict": "reject" | "flag" | "consistent"
        - "reason": str (explanation for verdict)
        - "max_speed_mph": float (computed from points)
    """
    # Handle empty or single point
    if len(points) <= 1:
        return {
            "verdict": "consistent",
            "reason": "Single point or no data; no spoofing indicators.",
            "max_speed_mph": 0.0
        }

    max_speed_mph = 0.0
    issues = []

    # Check each segment between consecutive points
    for i in range(len(points) - 1):
        curr = points[i]
        next_pt = points[i + 1]

        # Extract coordinates and timestamp
        lat1, lon1, ts1 = curr.get("lat"), curr.get("lon"), curr.get("timestamp")
        lat2, lon2, ts2 = next_pt.get("lat"), next_pt.get("lon"), next_pt.get("timestamp")

        # Check for timestamp issues (clock skew)
        time_delta = ts2 - ts1
        if time_delta < 0:
            issues.append("clock_skew")
            continue

        # Calculate distance
        distance_km = _haversine_distance_km(lat1, lon1, lat2, lon2)

        # Calculate speed
        speed_mph = _calculate_speed_mph(distance_km, time_delta)

        # Track maximum speed
        if speed_mph != float('inf') and speed_mph > max_speed_mph:
            max_speed_mph = speed_mph

        # Handle infinite speed (zero time delta with movement)
        if speed_mph == float('inf'):
            issues.append("impossible")
            max_speed_mph = float('inf')
        # Check for impossible speed (> 250 mph)
        elif speed_mph > 250:
            issues.append("impossible")
        # Check for unrealistic speed (> 120 mph)
        elif speed_mph > 120:
            issues.append("unrealistic")

    # Handle infinite speed
    if max_speed_mph == float('inf'):
        max_speed_mph = 999999.0  # Large number for serialization

    # Determine verdict based on issues found
    verdict = "consistent"
    reason = "Normal GPS movement pattern."

    if "impossible" in issues:
        verdict = "reject"
        reason = f"Impossible speed detected (GPS teleportation). Max speed: {max_speed_mph:.1f} mph."
    elif "unrealistic" in issues:
        verdict = "flag"
        reason = f"Unrealistic speed detected ({max_speed_mph:.1f} mph). Manual review recommended."
    elif "clock_skew" in issues:
        verdict = "flag"
        reason = "Clock skew detected (out-of-order timestamps). Device time may be corrupted."

    return {
        "verdict": verdict,
        "reason": reason,
        "max_speed_mph": max_speed_mph
    }
