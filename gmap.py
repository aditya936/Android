# Gmap api key quick check , save as .py -> exec as python3 gmap.py <KEY-HERE>

#!/usr/bin/env python3
# Requires: pip3 install requests
import sys, requests, json

if len(sys.argv) < 2:
    print("Usage: check_google_key.py <API_KEY>")
    sys.exit(2)

KEY = sys.argv[1]

ENDPOINTS = [
    ("Geocoding", f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={KEY}", "$5"),
    ("StaticMaps", f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=200x200&key={KEY}", "$2"),
    ("Streetview", f"https://maps.googleapis.com/maps/api/streetview?size=200x200&location=40.720032,-73.988354&key={KEY}", "$7"),
    ("Directions", f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={KEY}", "$5"),
    ("PlaceFind", f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=name&key={KEY}", "Varies"),
    ("Timezone", f"https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={KEY}", "$5"),
    ("Roads", f"https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796&key={KEY}", "$10"),
    ("Geolocate", f"https://www.googleapis.com/geolocation/v1/geolocate?key={KEY}", "Varies"),
]

print(f"Checking key: {KEY}\n")
for label, url, cost in ENDPOINTS:
    try:
        r = requests.get(url, timeout=10)
        code = r.status_code
        result = {}
        try:
            result = r.json()
        except ValueError:
            result = {"raw": r.text[:500]}

        # Detect common Google error structures
        status = "UNKNOWN"
        msg = ""
        if code == 200:
            # check if a top-level error exists
            if isinstance(result, dict) and ("error" in result or "error_message" in result or result.get("status") in ("REQUEST_DENIED","INVALID_REQUEST","OVER_QUERY_LIMIT")):
                # common message fields
                msg = result.get("error", {}).get("message") or result.get("error_message") or result.get("status") or ""
                if "not authorized" in str(msg).lower() or "request denied" in str(msg).lower():
                    status = "RESTRICTED"
                elif "invalid" in str(msg).lower():
                    status = "INVALID"
                elif "over_query_limit" in str(msg).lower() or "quota" in str(msg).lower():
                    status = "QUOTA_OR_BILLING"
                else:
                    status = "ERROR_RESPONSE"
            else:
                status = "OK_POSSIBLE_VALID"
        elif code == 403:
            status = "RESTRICTED_OR_AUTH"
            msg = result.get("error", {}).get("message") if isinstance(result, dict) else r.text[:300]
        elif code == 400:
            status = "INVALID"
            msg = result.get("error", {}).get("message") if isinstance(result, dict) else r.text[:300]
        else:
            status = f"HTTP_{code}"
            msg = result.get("error", {}).get("message") if isinstance(result, dict) else r.text[:300]

        print(f"{label:12} | {cost:7} | {status:20} | {msg}")
    except Exception as e:
        print(f"{label:12} | {cost:7} | ERROR               | {e}")
