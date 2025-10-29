# Android
android testing

------------
## Installing
```
- use 'apk extractor' on mobile to share apk
- share apk on drive
- download apk on gcp via cmd 'gdown "https://drive.google.com/uc?id=1Xg1fEf5L43SbmL2N0tW_FGJGjfEtYUQ7" -O gatehub.apk'
- change id with actual id & name
```

-----------
## scanning
1. ALL in one regex for sensitive leak ( regex from 'git1/dorks.txt') <br>
last dot start scanning from exec directory
```
grep -Eirn --color \
'(\$S\$[a-zA-Z0-9_/.]{52})|(\$P\$[a-zA-Z0-9_/.]{31})|(p8e-[a-z0-9]{32})|(AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58})|(LTAI[a-z0-9]{20})|(["'\'']AKC[a-zA-Z0-9]{10,}["'\''])|(["'\'']AP[0-9ABCDEF][a-zA-Z0-9]{8,}["'\''])|(A3T[A-Z0-9]{16}|AKIA[A-Z0-9]{16}|AGPA[A-Z0-9]{16}|AIDA[A-Z0-9]{16}|AROA[A-Z0-9]{16}|AIPA[A-Z0-9]{16}|ANPA[A-Z0-9]{16}|ANVA[A-Z0-9]{16}|ASIA[A-Z0-9]{16})|(da2-[a-z0-9]{26})|(:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+)|([A-Za-z0-9_ ,.\-]{0,25}(=|>|:=|\|\||:|<=|=>|:).{0,5}["'\''][A-Za-z0-9]{64}["'\''])|(sl.[A-Za-z0-9_-]{136})|(EAACEdEose0cBA[0-9A-Za-z]+)|((facebook|fb).{0,20}["'\''][0-9]{13,17})|(gh[upsor]_[0-9A-Za-z]{36})|(glpat-[0-9A-Za-z\-]{20})|(AIza[0-9A-Za-z_\-]{35})|(eyJrIjoi[a-z0-9_=\-]{72,92})|([Hh][Ee][Rr][Oo][Kk][Uu].{0,30}[0-9A-Fa-f\-]{36})|(["'\''][a-f0-9\-]{36}["'\''])|(NR(AK-[A-Z0-9]{27})|(JS-[a-f0-9]{19}))|(SG\.[A-Za-z0-9_.\-]{66})|(xox[baprs]-[0-9A-Za-z]{10,48})|(https://hooks.slack.com/services/T)|((sk|pk)_(test|live)_[0-9a-z]{10,32})|(k_live_[0-9A-Za-z]{24})|([0-9]+:AA[0-9A-Za-z\-_]{33})|(AQVN[A-Za-z0-9_\-]{35,38})|(YC[A-Za-z0-9_\-]{38})|([Ss][Ee][Cc][Rr][Ee][Tt].*["'\''][A-Za-z0-9]{32,45}["'\''])|(AC[a-f0-9]{32})|(NRAK-[A-Z0-9]{27})|(NRJS-[a-f0-9]{19})|(EAAAE[A-Za-z0-9_-]{59})|(ldap|ftp|sftp|host:|login|http://|https://|path:.*\.sql|password)' .
```
<br><br>
2. keywords for rce

```
grep -RInP --binary-files=without-match '\b(?:system|exec|sh|chmod|su|curl|wget|eval|runtime|loadlibrary|popen|dlopen|dlsym|fopen|strcpy|sprintf)\b|/bin' /path/to/dir
```
<br><br>
3. 
```
grep -rE -inI --binary-files=without-match --color=always \
'(AIza[0-9A-Za-z_\-]{35}|AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}|6L[0-9A-Za-z_\-]{38}|A[SK]IA[0-9A-Z]{16}|amzn\.mws\.[0-9a-f\-]{36}|s3\.amazonaws\.com|EAACEdEose0cBA[0-9A-Za-z]+|authorization[:= ]*(basic|bearer)\s+[A-Za-z0-9=:_\+\/\-]{20,100}|SK[0-9a-fA-F]{32}|sq0csp-[0-9A-Za-z_\-]{43}|sqOatp-[0-9A-Za-z_\-]{22}|sk_live_[0-9a-zA-Z]{24}|ghp_[a-zA-Z0-9]{36})' .


grep -rE -inI --binary-files=without-match --color=always \
'(-----BEGIN (RSA|DSA|EC|PGP|OPENSSH|SSH2|PRIVATE) PRIVATE KEY-----|ey[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*|xox[baprs]-[A-Za-z0-9\-]{10,48}|https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+|sl\.[A-Za-z0-9_\-]{16,50}|pk_live_[0-9a-zA-Z]{24}|ya29\.[0-9A-Za-z_\-]+|SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|glpat-[A-Za-z0-9\-]{20}|shpat_[A-Za-z0-9]{32}|LTAI[A-Za-z0-9]{12,20}|AKID[A-Za-z0-9]{13,20}|discord(app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_\-]{64,})' .

```

<br><br><br>


-----------------
## Gmap api key quick check
save as .py  -> exec as python3 gmap.py KEY-HERE

```
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
```
<br><br>


