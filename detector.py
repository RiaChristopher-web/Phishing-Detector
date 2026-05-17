from urllib.parse import urlparse
import re

# List of suspicious keywords
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "paypal",
    "signin",
    "password"
]

# URL shorteners commonly abused
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly"
]

def calculate_score(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    # 1. HTTPS check
    if not url.startswith("https://"):
        score += 2
        reasons.append("Does not use HTTPS")

    # 2. Long URL
    if len(url) > 75:
        score += 2
        reasons.append("URL is unusually long")

    # 3. Suspicious keywords
    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            score += 2
            reasons.append(f"Contains suspicious word: '{word}'")

    # 4. Too many dots
    if url.count(".") > 4:
        score += 1
        reasons.append("Too many dots in URL")

    # 5. Detect @ symbol
    if "@" in url:
        score += 3
        reasons.append("Contains '@' symbol")

    # 6. Detect IP address
    ip_pattern = r"(\\d{1,3}\\.){3}\\d{1,3}"
    if re.search(ip_pattern, parsed.netloc):
        score += 3
        reasons.append("Uses IP address instead of domain")

    # 7. URL shorteners
    for shortener in SHORTENERS:
        if shortener in parsed.netloc:
            score += 2
            reasons.append(f"Uses URL shortener: {shortener}")

    return score, reasons

def classify_url(score):
    if score >= 8:
        return "High Risk Phishing URL"
    elif score >= 4:
        return "Suspicious URL"
    else:
        return "Likely Safe"

def main():
    print("=" * 50)
    print("      PHISHING URL DETECTOR")
    print("=" * 50)

    url = input("Enter a URL to scan: ")

    score, reasons = calculate_score(url)
    result = classify_url(score)

    print("\nScan Result:")
    print(result)

    print(f"\nRisk Score: {score}/15")

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")

if __name__ == "__main__":
    main()
