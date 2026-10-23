# Bhejo builds

One folder per platform. Everything in here is something you can hand to a
person or attach to a message.

| Folder | What is in it | Status |
|---|---|---|
| `windows/` | `bhejo-0.1.0-windows.zip` — portable build with `Bhejo.cmd` | Ready |
| `macos/` | `bhejo-0.1.0-macos.zip` — portable build with `Bhejo.command` | Ready |
| `android/` | notes only | Not built — needs the Android SDK and a native app |
| `ios/` | notes only | Not built — needs a Mac, Xcode and an Apple Developer account |

The desktop zips are small (about 50 KB) because Bhejo has no dependencies.
They need Node.js 18.17 or newer installed once. The launcher starts the
receiver and opens the browser interface.

The website serves the same two zips from `docs/downloads/`. If you rebuild one,
copy it to both places.

Contact: jdmibusiness01@gmail.com
