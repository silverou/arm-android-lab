# arm-android-lab

ARM64 native Android container lab (redroid on GitHub Actions arm64 runners).

Goal: run an ARM64 Android app natively (no x86 translation) with root,
for runtime instrumentation and traffic capture.

## Workflows

- `probe.yml` — verifies binder/binderfs availability on the runner and boots
  a redroid container, reporting guest props and adb access.

## Status

Probe stage. App payload is not part of this repository.
