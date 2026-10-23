# Android

`bhejo-0.1.0.apk` — 8.8 MB, Android 10 (API 29) and newer, no Node.js needed.

This is the native Kotlin app from [`android/`](../android/). It speaks the same
protocol as the desktop build: multicast discovery on `224.0.0.167:53317`,
TLS with a persisted self-signed certificate, fingerprint pinning, optional PIN,
and SHA-256 checked on both ends.

## Install

1. Copy the APK to the phone (USB, email to yourself, or download it from the
   website).
2. Open it. Android asks to allow installs from this source; allow it for the
   app you used to open the file, install, then turn the permission back off.
3. Open Bhejo. The phone starts receiving immediately and shows its own
   fingerprint.

Play Protect may show "unrecognised app" because the APK is signed with a
self-generated key rather than a Play Store key. That is expected for a
direct install.

## Checksum

```
SHA-256  33246bb4977cb90f83bb4b8236902bf8bd71f01bdb6868471426f680ee0b5798
```

Verify with `certutil -hashfile bhejo-0.1.0.apk SHA256` on Windows or
`shasum -a 256 bhejo-0.1.0.apk` on macOS. The same line is published next to
the download as `bhejo-0.1.0-android.apk.sha256`.

## Use

- **Receive:** on the computer run `bhejo receive`, then `bhejo send <files>
  --to <phone>`. Accept the dialog on the phone. Files are saved to
  `Downloads/Bhejo`.
- **Send:** tap **Choose files**, pick one or more, then either tap a device in
  **Nearby** or use **Add a computer by IP** and type the address printed by
  `bhejo receive`. Confirm the fingerprint once; it is pinned from then on.
- **PIN:** if the receiver requires one, type it in the PIN field before you
  send. If you set a PIN on the phone, incoming senders must know it too.
- Long-press a saved computer to forget its pinned fingerprint.

## Limits

- The app must stay in the foreground while receiving. There is no foreground
  service yet, so Android stops the server when the app is backgrounded.
- Guest Wi-Fi with client isolation blocks transfers; the devices must be able
  to reach each other.
- No resume: an interrupted file restarts from zero.

Signed with the release key in `android/keystore/` (not committed). Keep a copy
of that keystore: updates, including any future Play Store release, must be
signed with the same key.

Contact: jdmibusiness01@gmail.com
