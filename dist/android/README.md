# Android

**No APK yet.** This folder is intentionally empty of binaries.

## Why

Bhejo is a Node.js process plus a local web interface. Android cannot run that
process without Termux, and an APK that simply wraps the web page would have
nothing to talk to. A real Android app has to be written natively (Kotlin) and
implement the same discovery and transfer protocol:

- multicast announcement on `224.0.0.167:53317`
- HTTPS receiver with a persisted self-signed certificate
- fingerprint pinning and the optional PIN
- streaming upload with SHA-256 verification

## What works today

Install Termux from F-Droid, then:

```bash
pkg install nodejs git
git clone https://github.com/rushi0105/bhejo.git
cd bhejo
node bin/bhejo.mjs receive
```

Open `http://127.0.0.1:53318` in the phone's browser. This is the honest
workaround, not a finished product.

## What is needed to ship the APK

- Android SDK command-line tools and a JDK (Java 21 is already on the development
  machine, the SDK is not)
- a native Android project, around 1–2 weeks of work for a first version
- your Google Play developer account ($25 one time, identity verification)
- a signed release (`.aab`), a privacy policy URL, and the Data safety form —
  the policy page already exists at <https://rushi0105.github.io/bhejo/privacy.html>

Contact: jdmibusiness01@gmail.com
