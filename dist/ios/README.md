# iOS / App Store

**No app yet.** This folder is intentionally empty of binaries.

## Why

An iPhone cannot run Bhejo today. The app must be native (Swift), and building
it requires a Mac with Xcode. Neither exists on the current development machine,
and Apple requires code signing with a paid developer account before anything
can be installed on a real phone, let alone submitted.

## What is needed to ship it

- a Mac with Xcode 16 or newer
- an Apple Developer Program membership ($99 per year)
- a native Swift app that implements discovery (Bonjour or multicast),
  an HTTPS receiver with a persisted certificate, pinning, and streaming upload
- App Store review, plus the privacy policy and App Privacy answers — the policy
  page already exists at <https://rushi0105.github.io/bhejo/privacy.html>

Until then the honest answer on iOS is: use AirDrop for two Apple devices, and
Bhejo for everything else.

Contact: jdmibusiness01@gmail.com
