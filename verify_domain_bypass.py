from urllib.parse import urlparse

# Replicating the exact logic in WebViewFragment.copydefault(String url)
def copydefault(url_str):
    allowlist = ["safaricom.co.ke", "masoko.com"]
    try:
        parsed = urlparse(url_str)
        host = parsed.hostname
        if not host:
            return False
        for allowed in allowlist:
            if allowed in host: # Java String.contains()
                return True
        return False
    except Exception as e:
        return False

# Test legitimate URLs
print("=== Legitimate URLs ===")
for url in ["https://www.safaricom.co.ke/personal", "https://masoko.com/shop"]:
    print(f"  {url:45} -> Allowed: {copydefault(url)}")

# Test attacker-controlled domains bypassing the allowlist
print("\n=== Attacker-Controlled Exploit Domains ===")
attacker_urls = [
    "https://safaricom.co.ke.attacker.com/exploit.html",
    "https://attacker-safaricom.co.ke.com/payload",
    "https://masoko.com.evil.org/steal_token",
    "https://evil-masoko.com/index.html",
    "https://sub.sub.safaricom.co.ke.malicious-site.com/poc"
]
for url in attacker_urls:
    print(f"  {url:55} -> Allowed: {copydefault(url)}")
