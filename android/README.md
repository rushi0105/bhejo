# Bhejo for Android

The phone half of Bhejo. Same discovery beacon, same TLS protocol, same
fingerprint pinning as the desktop build, written natively in Kotlin so it does
not need Termux or Node on the phone.

## What it does

- Receives files from a computer running `bhejo receive` and saves them to
  `Downloads/Bhejo` through MediaStore (no storage permission needed).
- Sends files the other way: pick files with the system picker, tap a device in
  the Nearby list.
- Optional PIN, checked on the receiving side and sent by the other side.
- Every transfer is TLS with a self-signed certificate whose SHA-256
  fingerprint is learned from the discovery beacon and pinned before a single
  byte is written.

## Requirements

- Android 10 (API 29) or newer.
- Both devices on the same Wi-Fi network. Routers that block multicast still
  work through the broadcast fallback; client isolation (guest Wi-Fi) does not.
- To build: JDK 17 or newer, Android SDK with platform 34 and build-tools
  34.0.0, Gradle 8.7+.

## Build

```bash
cd android
# local.properties must point at the SDK:
#   sdk.dir=/path/to/Android/Sdk
./gradlew assembleRelease      # gradlew.bat on Windows
```

The APK lands in `app/build/outputs/apk/release/app-release.apk`.

Release signing reads `android/keystore.properties`:

```
storeFile=keystore/bhejo-release.jks
storePassword=...
keyAlias=bhejo
keyPassword=...
```

Neither that file nor the keystore is committed. Keep a copy of
`android/keystore/bhejo-release.jks` somewhere safe: Play Store updates must be
signed with the same key, and losing it means publishing under a new package.

Without `keystore.properties` the build still works; the release APK is then
unsigned (or signed with the debug key when using `assembleDebug`).

## Layout

```
app/src/main/java/dev/bhejo/app/
  Identity.kt       persistent keypair + self-signed certificate, fingerprint
  Discovery.kt      UDP beacon on 224.0.0.167:53317 + broadcast fallback
  TlsHttpServer.kt  minimal HTTPS server over SSLServerSocket
  Receiver.kt       /api/v1/{info,prepare-upload,upload,cancel}
  Sender.kt         pinned TLS client, streaming upload, SHA-256 check
  MainActivity.kt   one screen, programmatic views, no UI framework
```

BouncyCastle is used only to build the self-signed certificate; the TLS stack
itself is the platform's.

## Limits in 0.1.0

- The screen must stay open while receiving. There is no foreground service
  yet, so Android stops the server when the app is backgrounded.
- Discovery needs the app in the foreground to answer beacons.
- No transfer history and no "resume"; a dropped connection restarts the file.
