from flask import Flask, render_template, request
import re
import validators
import tldextract

app = Flask(__name__)

# List of blacklisted domains (expand with known phishing domains)
BLACKLISTED_DOMAINS = [
    "phishy-bank.com",
    "secure-login.bank-secure.com",
    "fake-paypal-login.com",
]

# Check if the URL uses HTTPS
def is_https(url):
    return url.startswith("https://")

# Check for IP-based URLs
def is_ip_based(url):
    ip_pattern = r"^(http://|https://)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$"
    return bool(re.match(ip_pattern, url))

# Check for shortened URLs
def is_shortened_url(url):
    shortened_domains = [
        "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly"
    ]
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain in shortened_domains

# Check for suspicious domain names (e.g., typosquatting or subdomain abuse)
def is_suspicious_domain(url):
    extracted = tldextract.extract(url)
    domain = extracted.domain
    subdomain = extracted.subdomain
    full_domain = f"{extracted.domain}.{extracted.suffix}"

    # Example typosquatting patterns
    suspicious_keywords = ["secure", "login", "verify", "update", "bank"]
    for keyword in suspicious_keywords:
        if keyword in domain or keyword in subdomain:
            return True

    # Check if the domain is in the blacklist
    if full_domain in BLACKLISTED_DOMAINS:
        return True

    return False

# Analyze the URL for phishing indicators
def analyze_url(url):
    if not validators.url(url):
        return {"status": "Invalid URL", "phishing_score": 0}

    phishing_score = 0
    reasons = []

    # Check for HTTPS
    if not is_https(url):
        phishing_score += 30
        reasons.append("The URL does not use HTTPS.")

    # Check for IP-based URL
    if is_ip_based(url):
        phishing_score += 20
        reasons.append("The URL uses an IP address instead of a domain name.")

    # Check for shortened URL
    if is_shortened_url(url):
        phishing_score += 20
        reasons.append("The URL is a shortened link, which is often used in phishing.")

    # Check for suspicious domains
    if is_suspicious_domain(url):
        phishing_score += 50
        reasons.append("The domain name or subdomain appears suspicious.")

    # Cap the phishing score at 100
    phishing_score = min(phishing_score, 100)

    # Return the analysis results
    if phishing_score > 50:
        status = "Phishing suspected"
    else:
        status = "Likely safe"

    return {
        "status": status,
        "phishing_score": phishing_score,
        "reasons": reasons,
    }

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        analysis_result = analyze_url(url)
        return render_template("result.html", result=analysis_result, url=url)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
