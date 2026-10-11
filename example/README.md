# http_security_pinning example

A small app that pins HTTPS requests made with `package:http` and `package:dio`.

1. Enter a URL and tap **Discover pins**: the app connects with a pin that
   cannot match and shows the SPKI pins the server presented
   (`NoValidPinsFoundException.observedPins`). Verify them out of band, for
   example with `openssl`, before shipping them.
2. Keep at least two pins (a primary and a backup) and tap
   **Make request with http** or **Make request with dio**.

## Tests

On-device integration tests (Android or iOS device; need Internet access):

```bash
flutter test integration_test
```

Native unit tests:

```bash
# Android (JUnit), after `flutter build apk --debug` once
cd android && ./gradlew :http_security_pinning:testDebugUnitTest

# iOS (XCTest, macOS only), after `flutter build ios --config-only --simulator`
xcodebuild test -workspace ios/Runner.xcworkspace -scheme Runner \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```
