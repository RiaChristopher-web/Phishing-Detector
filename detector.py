from urllib.parse import urlparse
import re

# Suspicious keywords
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

# URL shorteners
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly"
]

# Load blacklist from file
def load_blacklist():
    try:
        with open("blacklist.txt", "r") as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print("Blacklist file not found.")
        return []

BLACKLIST = load_blacklist()

def calculate_score(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    # HTTPS check
    if not url.startswith("https://"):
        score += 2
        reasons.append("Does not use HTTPS")

    # Long URL
    if len(url) > 75:
        score += 2
        reasons.append("URL is unusually long")

    # Suspicious keywords
    for word in SUSPICIOUS_WORDS:
        if word in url.lower():
            score += 2
            reasons.append(f"Contains suspicious word: '{word}'")

    # Too many dots
    if url.count(".") > 4:
        score += 1
        reasons.append("Too many dots in URL")

    # @ symbol
    if "@" in url:
        score += 3
        reasons.append("Contains '@' symbol")

    # IP address detection
    ip_pattern = r"(\\d{1,3}\\.){3}\\d{1,3}"
    if re.search(ip_pattern, parsed.netloc):
        score += 3
        reasons.append("Uses IP address instead of domain")

    # URL shorteners
    for shortener in SHORTENERS:
        if shortener in parsed.netloc:
            score += 2
            reasons.append(f"Uses URL shortener: {shortener}")

    # Blacklist check
    for bad_site in BLACKLIST:
        if bad_site in url:
            score += 5
            reasons.append(f"Blacklisted domain detected: {bad_site}")

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
    print("        PHISHING URL DETECTOR")
    print("=" * 50)

    url = input("Enter a URL to scan: ")

    score, reasons = calculate_score(url)
    result = classify_url(score)

    print("\nScan Result:")
    print(result)

    print(f"\nRisk Score: {score}")

    if reasons:
        print("\nReasons:")
        for reason in reasons:
            print(f"- {reason}")

if __name__ == "__main__":
    main()
