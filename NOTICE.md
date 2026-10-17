# Third-party UI

This product includes UI code from the user-supplied Ruru-1.1.1 source archive,
which contains code credited to Nullptr and byxiaorun and licensed under the
Apache License, Version 2.0. The original license is preserved in LICENSE-Ruru.md.

Type.kt and IDetector.kt are copied unchanged. Theme.kt additionally styles the
navigation bar and its icons; the Ruru light/dark/dynamic color palettes remain.
CheckCard.kt is reused with detail-row status icons moved to a fixed leading
column aligned with each result's first text baseline, as requested by the user.
IconHintCard.kt retains the original icons and layout; its gettext import changes.
MainPage.kt and MainActivity.kt retain Ruru's Compose layout and components while
replacing the detector data source and adding Prism actions to the About dialog.
Version 1.2.0 adds a GitHub link, explicit system-bar/cutout insets, bottom scroll
clearance and a secondary-check disclosure using Ruru's card/arrow/spring style.
The original source is preserved in vendor-ui/Ruru-1.1.1 for comparison.

The launcher image was supplied by the user. The reference APK's certificate is
used as a comparison baseline, and does not sign PrismDetector.
