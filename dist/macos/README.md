# macOS

**File:** `bhejo-0.1.0-macos.zip` (portable, about 50 KB)

1. Install Node.js 18.17 or newer once: <https://nodejs.org>
2. Unzip anywhere.
3. Double-click `Bhejo.command`.

If macOS refuses to open it, the archive lost its Unix permissions — that is
normal for a zip built on Windows. Fix it once in Terminal:

```bash
cd ~/Downloads/bhejo
chmod +x Bhejo.command
open Bhejo.command
```

Or run it directly:

```bash
./Bhejo.sh
```

The browser opens `http://127.0.0.1:53318`. Keep the Terminal window open.

The build is architecture-independent (plain Node), so it runs on Intel and
Apple silicon. On first run macOS asks whether to allow incoming connections —
allow it.
