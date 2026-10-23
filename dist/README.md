# Bhejo builds

One folder per platform. Everything in here is something you can hand to a
person or attach to a message.

| Folder | What is in it | Status |
|---|---|---|
| `windows/` | `bhejo-0.1.0-windows.zip` — portable build with `Bhejo.cmd` | Ready |
| `macos/` | `bhejo-0.1.0-macos.zip` — portable build with `Bhejo.command` | Ready |
| `android/` | `bhejo-0.1.0.apk` — native Kotlin app, Android 10+ | Ready |
| `ios/` | notes only | Not built — needs a Mac, Xcode and an Apple Developer account |

The desktop zips are small (about 50 KB) because Bhejo has no dependencies.
They need Node.js 18.17 or newer installed once. The launcher starts the
receiver and opens the browser interface.

The Android APK is self-contained: no Node.js, no store account. Install it,
keep the screen open while receiving, and files land in `Downloads/Bhejo`.

The website serves the same three builds from `docs/downloads/`. If you rebuild
one, copy it to both places.

Contact: jdmibusiness01@gmail.com
