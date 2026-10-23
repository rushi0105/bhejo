# Windows

**File:** `bhejo-0.1.0-windows.zip` (portable, about 49 KB)

1. Install Node.js 18.17 or newer once: <https://nodejs.org>
2. Unzip anywhere.
3. Double-click `Bhejo.cmd`.
4. The browser opens `http://127.0.0.1:53318` — that page is the app.

Firewall asks once on first run. Allow it on **private networks**.

Works on Windows 10 and 11, x64 and arm64, because it is plain Node.

To receive into a different folder:

```bat
Bhejo.cmd --dir "C:\Users\you\Downloads"
```

There is no installer and no registry entry. Delete the folder to remove it.
