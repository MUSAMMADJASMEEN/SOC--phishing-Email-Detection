import re

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "suspended",
    "immediately",
    "click the link",
    "action required",
    "password",
    "confirm your details"
]

def analyze_email(email_text):
    findings = []

    email_lower = email_text.lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in email_lower:
            findings.append(f"Suspicious keyword: {keyword}")

    urls = re.findall(r"https?://\S+", email_text)

    if urls:
        findings.append(f"URL detected: {len(urls)}")

    if findings:
        return {
            "status": "SUSPICIOUS",
            "findings": findings
        }

    return {
        "status": "NO OBVIOUS THREATS",
        "findings": []
    }


if __name__ == "__main__":
    print("SOC Phishing Email Detector")
    print("=" * 30)

    sample_email = """
    Subject: Urgent: Verify Your Account

    Your account will be suspended unless you verify your identity immediately.

    Click the link below:
    http://example.com/verify
    """

    result = analyze_email(sample_email)

    print("Status:", result["status"])

    for finding in result["findings"]:
        print("-", finding)
