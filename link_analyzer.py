from urllib.parse import urlparse
import ipaddress
def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

url = input("Enter a URL to analyze: ")
parsed_url = urlparse(url)

print("welcome to ScamShield AI")
print("Domain:", parsed_url.hostname)
print("HTTPS:", parsed_url.scheme == "https")
print("IP Address Detected:", is_ip_address(parsed_url.hostname))
print("@ Symbol Detected:", "@" in parsed_url.netloc)
suspicious_keywords = ["verify", "urgent", "password", "reset", "suspended"]
found_keywords = [word for word in suspicious_keywords if word in url.lower()]
print("Suspicious Keywords Found:", found_keywords)
risk_score = 0
warnings = []
if found_keywords:
    risk_score += 20
    warnings.append("Suspicious keywords detected in URL")
if parsed_url.scheme == "http":
    risk_score += 10
    warnings.append("This URL uses HTTP instead of HTTPS")
if is_ip_address(parsed_url.hostname):
    risk_score += 15
    warnings.append("This URL uses an IP address instead of a domain name")
if "@" in parsed_url.netloc:
    risk_score += 20
    warnings.append("This URL contains an @ symbol that may disguise its Destination")
print("Risk Score:", risk_score)
risk_level = "Low Risk"
if risk_score >= 40:
    risk_level = "High Risk"
elif risk_score >= 20:
    risk_level = "Medium Risk"
print("Risk Level:", risk_level)
print("Note: This score is a preliminary check, not a guarantee of safety.")
print("Security Warnings:")
for warnings in warnings:
    print("-", warnings)
if not warnings:
    print("- No warnings signs detected")
