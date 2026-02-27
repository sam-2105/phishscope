#!/bin/bash

# =============================
# PhishScope - Bash Phishing Detector
# =============================

TARGET="$1"

if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <url or domain>"
    exit 1
fi

RISK_SCORE=0
REPORT=""

# ---------- Risk Function ----------
add_risk() {
    local points=$1
    local reason=$2
    RISK_SCORE=$((RISK_SCORE + points))
    REPORT+="- [$points] $reason\n"
}

# ---------- Extract Domain ----------
DOMAIN=$(echo "$TARGET" | awk -F/ '{print $3}')
DOMAIN=${DOMAIN:-$TARGET}

echo "[*] Target: $TARGET"
echo "[*] Domain: $DOMAIN"
echo

# ---------- Entropy Function ----------
entropy() {
    str="$1"
    awk -v str="$str" '
    BEGIN {
        split(str, arr, "")
        for (i in arr) freq[arr[i]]++
        len=length(str)
        for (c in freq) {
            p=freq[c]/len
            H += -p*log(p)/log(2)
        }
        print H
    }'
}

# ---------- Entropy Check ----------
ENT=$(entropy "$DOMAIN")
echo "[*] Domain Entropy: $ENT"

if (( $(echo "$ENT > 3.8" | bc -l) )); then
    add_risk 15 "High entropy domain (random-looking)"
fi

# ---------- Suspicious Keywords ----------
KEYWORDS=("login" "verify" "account" "secure" "update" "bank" "paypal")

for word in "${KEYWORDS[@]}"; do
    if [[ "$TARGET" == *"$word"* ]]; then
        add_risk 10 "Suspicious keyword: $word"
    fi
done

# ---------- Domain Age ----------
echo "[*] Checking domain age..."

WHOIS=$(whois "$DOMAIN" 2>/dev/null)

CREATION=$(echo "$WHOIS" | grep -i "Creation Date" | head -n1 | awk '{print $3}')

if [[ -n "$CREATION" ]]; then
    YEAR=$(date -d "$CREATION" +%Y 2>/dev/null)
    CURRENT=$(date +%Y)

    AGE=$((CURRENT - YEAR))

    echo "[*] Domain Age: $AGE years"

    if [[ $AGE -le 1 ]]; then
        add_risk 20 "New domain (≤ 1 year)"
    fi
else
    add_risk 10 "Unable to determine domain age"
fi

# ---------- Redirect Analysis ----------
echo "[*] Checking redirects..."

REDIRECTS=$(curl -Ls -o /dev/null -w %{url_effective} "$TARGET")

if [[ "$REDIRECTS" != "$TARGET" ]]; then
    add_risk 10 "Redirect detected -> $REDIRECTS"
fi

# ---------- SSL Certificate ----------
echo "[*] Checking SSL..."

SSL_INFO=$(echo | openssl s_client -connect "$DOMAIN:443" 2>/dev/null)

if echo "$SSL_INFO" | grep -q "self signed"; then
    add_risk 25 "Self-signed SSL certificate"
fi

if ! echo "$SSL_INFO" | grep -q "Verify return code: 0"; then
    add_risk 10 "SSL verification issue"
fi

# ---------- Content Scan ----------
echo "[*] Fetching page content..."

CONTENT=$(curl -Ls "$TARGET")

PHISH_TERMS=("password" "credit card" "ssn" "urgent" "verify now")

for term in "${PHISH_TERMS[@]}"; do
    if echo "$CONTENT" | grep -iq "$term"; then
        add_risk 5 "Phishing content keyword: $term"
    fi
done

# ---------- Final Risk ----------
echo
echo "=============================="
echo " PHISHING RISK REPORT"
echo "=============================="

echo -e "$REPORT"

echo "Total Score: $RISK_SCORE"

if [[ $RISK_SCORE -ge 60 ]]; then
    LEVEL="HIGH RISK"
elif [[ $RISK_SCORE -ge 30 ]]; then
    LEVEL="MEDIUM RISK"
else
    LEVEL="LOW RISK"
fi

echo "Risk Level: $LEVEL"

# ---------- JSON Output ----------
echo
echo "{"
echo "  \"target\": \"$TARGET\","
echo "  \"domain\": \"$DOMAIN\","
echo "  \"risk_score\": $RISK_SCORE,"
echo "  \"risk_level\": \"$LEVEL\""
echo "}"
