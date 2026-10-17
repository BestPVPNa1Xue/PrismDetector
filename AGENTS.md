# PrismDetector development and delivery

- Preserve the Ruru Compose components, icons, theme and animations. Apply requested layout changes narrowly. Detection rules and result classification belong in C++; Kotlin/Java bridge platform APIs and display results.
- The user has requested source publication for each delivered change at https://github.com/BestPVPNa1Xue/PrismDetector.git. Unless a later instruction says otherwise, deliver a versioned source commit and an annotated `vX.Y.Z` tag, and push both after relevant validation. Never replace an existing release tag or force-push history.
- Keep application versionName, versionCode, native report version and build/export filenames consistent. Preserve the preceding APK/source baseline locally.
- Build the release, run full lint and verify signing/alignment. Test changed behavior on the dedicated emulator; do not modify personal devices. Report ARM64/API coverage accurately.
- Publish source, resources, build wrappers, licenses and concise release records. Do not publish signing keys, SDK/AVD caches, user-provided APKs, raw device reports/IDs, private local paths or reverse-engineering databases. Keep these local.
- Preserve upstream repository history and Ruru's Apache-2.0 attribution. Confirm remote commit/tag IDs after pushing before reporting publication success.
