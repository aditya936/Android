# Android
android testing
-----------------

| Flag   | Meaning                                                                       |
| ------ | ----------------------------------------------------------------------------- |
| **-E** | Use **Extended regex** (allows `+`, `?`, `                                    |
| **-R** | **Recursive**, follow directories **and symlinks**.                           |
| **-r** | **Recursive**, but **don’t follow symlinks**.                                 |
| **-i** | **Ignore case** (case-insensitive match).                                     |
| **-I** | **Ignore binary files** (skip non-text files).                                |
| **-n** | Show **line numbers**.                                                        |
| **-P** | Use **Perl-compatible regex (PCRE)** (supports `\w`, `\s`, lookaheads, etc.). |
| **-o** | Show **only the matched part** (not the whole line).                          |

<br>

```
grep -rE -inI  -> print whole line which is too long and garbage -> 3.
grep -RInPo    -> only print token/leak -> 1.
grep -Eirn     -> print leak with few words of both side -> 2. 
```
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

# This is from regex.txt
```
part 1

grep -Eirn --binary-files=without-match '"type": "service_account"|(([a-z0-9_ .,\\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}["'']([a-z0-9]{32})["''])|(?i)(bs|bugsnag)(.{0,20})?[0-9a-f]{32}|(?i)(facebook|fb)(.{0,20})?(?-i)["''][0-9a-f]{32}["'']|(?i)(facebook|fb)(.{0,20})?["''][0-9]{13,17}["'']|(?i)[fF][aA][cC][eE][bB][oO][oO][kK].*["'']?[0-9a-f]{32}["'']?|(?i)[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}|(?i)\b(?:twilio|tw)\s*[_-]?account[_-]?sid\s*[:=]\s*["'']?AC[a-zA-Z0-9_-]{32}["'']?|(?i)\b(?:twitter|tw)\s*[_-]?access[_-]?token\s*[:=]\s*["'']?[0-9]+-[0-9a-zA-Z]{40}["'']?|(?i)\b(?:twitter|tw)\s*[_-]?oauth[_-]?token\s*[:=]\s*["'']?[0-9a-zA-Z]{35,44}["'']?|(?i)\b(gh[pousr]_[0-9a-zA-Z]{36})\b|(?i)\bapi[_-]?key\s*[:=]\s*["'']?[a-zA-Z0-9_-]{20,100}["'']?|(?i)\bapi[_-]?key\s*[:=]\s*["'']?[0-9a-zA-Z]{32,45}["'']?|(?i)\bauthorization\s*:\s*basic\s+[a-zA-Z0-9=:_+/.-]{20,100}|(?i)\bauthorization\s*:\s*bearer\s+[a-zA-Z0-9_.=:_+/ -]{20,100}|(?i)\bsecret\s*[:=]\s*["'']?[0-9a-zA-Z]{32,45}["'']?|(?i)^AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9]{30,45}$|(?i)^[A-Za-z0-9]{32}\.[A-Za-z0-9]{16}$|(?i)^[A-Za-z0-9]{44}=[A-Za-z0-9+/=]{0,43}$|(?i)^[a-z]+://[^/]*:[^@]+@|(?i)^sl\.[A-Za-z0-9_-]{16,50}$|(?i)adobe(.{0,20})?["''][A-Za-z0-9]{32,56}["'']|(?i)aws(.{0,20})?(?-i)["''][0-9A-Za-z/+]{40}["'']|(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?i)linkedin(.{0,20})?(?-i)[0-9a-z]{12}|(?i)linkedin(.{0,20})?[0-9a-z]{16}|(?i)netlify(.{0,20})?["''][0-9A-Za-z]{40}["'']|(?i)stripe(.{0,20})?[sr]k_live_[0-9A-Za-z]{24}|(?i)twilio(.{0,20})?SK[0-9a-f]{32}|(?i)twitter(.{0,20})?[0-9a-z]{18,25}|(?i)twitter(.{0,20})?[0-9a-z]{35,44}|(?i)zoom(.{0,20})?["''][0-9A-Za-z_.-]{36,160}["'']' /path/to/targets --exclude-dir=.git || true


part 2

grep -Eirn --binary-files=without-match '(YC[a-zA-Z0-9_-]{38})|([-]+BEGIN [^[:space:]]+ PRIVATE KEY[-]+[[:space:]]*[^-]*[-]+END [^[:space:]]+ PRIVATE KEY[-]+)|([0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)|([a-z0-9._-]+\.firebaseio\.com|[a-z0-9._-]+\.firebaseapp\.com)|([a-zA-Z0-9._-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9._-]+|s3-[a-zA-Z0-9._/]+|s3.amazonaws.com/[a-zA-Z0-9._-]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9._-]+)|([fF][aA][cC][eE][bB][oO][oO][kK]|[fF][bB])(.{0,20})?["''][0-9]{13,17}|(ghu|ghs)_[0-9A-Za-z]{36}|(google|gcp|youtube|drive|yt)(.{0,20})?["'']AIza[0-9A-Za-z_-]{35}["'']|(p8e-)[a-z0-9]{32}|(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9A-Za-z]{24}|(us-east-1|us-east-2|us-west-1|us-west-2|sa-east-1):[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12}|-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|-----BEGIN DSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----|-----BEGIN RSA PRIVATE KEY-----|00D[0-9A-Za-z]{15,18}![A-Za-z0-9]{40}|00[0-9A-Za-z]{20}\$[0-9A-Za-z]{6,}|00[A-Za-z0-9]{30}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}|6L[0-9A-Za-z_-]{38}|^6[0-9A-Za-z_-]{39}$|AIza[0-9A-Za-z_-]{35}|AP[A-Za-z0-9_-]{32}|A[0-9a-f]{32}|A[SK]IA[0-9A-Z]{16}|EAAAE[A-Za-z0-9_-]{59}|EAACEdEose0cBA[0-9A-Za-z]+|GR1348941[A-Za-z0-9=_-]{20,40}|IGQV[A-Za-z0-9._-]{10,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|SG\.[\w_]{16,32}\.[\w_]{16,64}|SK[0-9a-fA-F]{32}|[0-9]+:AA[0-9A-Za-z_-]{33}' decompileee/ --exclude-dir=.git || true


part 3

grep -Eirn --binary-files=without-match '[0-9]{8,10}:AA[0-9A-Za-z_-]{35}|[0-9a-f]{32}-us[0-9]{1,2}|[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}|[A-Za-z0-9._%:+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Za-z]{3,10}://[^/[:space:]@:]{3,20}:[^/[:space:]@:]{3,20}@.{1,100}["'']|\bAKIA[0-9A-Z]{16}\b|\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b|\bghp_[A-Za-z0-9]{36}\b|access_token=[A-Za-z0-9]+|access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}|amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|arn:aws:sns:[a-z0-9-]+:[0-9]+:[A-Za-z0-9_-]+|cisco[A-Za-z0-9]{30}|cloudinary://[0-9]{15}:[0-9A-Za-z_-]+@[0-9A-Za-z_-]+|da2-[a-z0-9]{26}|ddapi_[A-Za-z0-9]{32}|dop_v1_[0-9a-f]{64}|dt0[A-Za-z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}|ey[A-Za-z0-9_=+.-]+\.[A-Za-z0-9_=+.-]+\.?[A-Za-z0-9_=+./-]*$|gho_[0-9A-Za-z]{36}|ghr_[0-9A-Za-z]{76}|glpat-[0-9A-Za-z_-]{20}' decompileee/ --exclude-dir=.git || true
 

part 4

grep -Eirn --binary-files=without-match 'glpat-[0-9A-Za-z-]{20}|https://[a-z0-9-]+\.firebaseio\.com|https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{64,}|https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+|https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}|key-[0-9A-Za-z]{32}|pk\.[A-Za-z0-9]{60}\.[A-Za-z0-9]{22}|pk_live_[0-9A-Za-z]{24}|pk_test_[0-9A-Za-z]{24}|rk_live_[0-9A-Za-z]{24}|s3\.amazonaws\.com/+|[A-Za-z0-9_-]*\.s3\.amazonaws\.com|sentry_auth_token_[0-9A-Za-z]{70}|shpat_[A-Fa-f0-9]{32}|shpca_[A-Fa-f0-9]{32}|shppa_[A-Fa-f0-9]{32}|shpss_[A-Fa-f0-9]{32}|sk_live_[0-9a-z]{32}|sk_[A-Za-z0-9]{32}|sk_live_[0-9A-Za-z]{24}|sk_live_[0-9a-z]{32}|sk_test_[0-9A-Za-z]{24}|sq0atp-[0-9A-Za-z_-]{22}|sq0csp-[0-9A-Za-z_-]{43}|sqOatp-[0-9A-Za-z_-]{22}|EAAA[A-Za-z0-9]{60}|tiktok_access_token=[A-Za-z0-9_]+|xox[baprs]-[0-9A-Za-z]{10,48}|xoxb-[A-Za-z0-9-]{24,34}|xoxp-[A-Za-z0-9-]{24,34}|xoxs-[0-9]{1,9}\.[0-9A-Za-z]{1,12}\.[0-9A-Za-z]{24,64}|ya29\.[0-9A-Za-z_-]+' decompileee/ --exclude-dir=.git || true  

```

