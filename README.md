# HttpSecurityPinning

[![pub version](https://img.shields.io/pub/v/http_security_pinning.svg)](https://pub.dev/packages/http_security_pinning)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A Flutter plugin that provides a secure-by-default `HttpClient` implementation with certificate pinning against SPKI hashes.

This package helps prevent man-in-the-middle (MITM) attacks by ensuring your app only communicates with servers presenting a trusted certificate.

## Features

- **SPKI Pinning**: Pins certificates against their Subject Public Key Info (SPKI) SHA-256 hash.
- **Easy Integration**: Works seamlessly with popular packages like `http` and `dio`.
- **Configurable**: Set custom timeouts and retry counts for certificate fetching.
- **Global Configuration**: Optionally apply pinning to all `HttpClient` instances in your app using `HttpOverrides`.
- **Robust Error Handling**: Provides clear, catchable exceptions for pinning failures.
- **Automatic Hash Logging**: Logs the certificate chain's SPKI hashes to the console to simplify setup.

## Supported Platforms

This plugin is currently available for the following platforms:

- ✅ **Android** (API 19+)
- ✅ **iOS** (iOS 10.0+)

## Getting Started

Add the package to your `pubspec.yaml`:

```yaml
dependencies:
  http_security_pinning: ^1.0.0 # Replace with the latest version
```

Then, run `flutter pub get`.

## Usage

The easiest way to use this package is to create an instance of `HttpSecurityPinningClient`.

### Configuration

You can configure the client with a specific timeout for fetching certificates and a retry count.

```dart
final secureClient = HttpSecurityPinningClient(
  ["YOUR_SPKI_HASH_HERE"],
  timeout: const Duration(seconds: 15), // Default is 10 seconds
  retryCount: 2, // Default is 3
);
```

### Finding Your SPKI Hash

To get the SPKI hash for your server, make a request using the client without any pins (or with an incorrect pin). The client will fail the connection but will log all SPKI hashes from the server's certificate chain to the debug console. Look for a line like:

`I/HttpSecurityPinningClient(12345): Certificate chain for your.domain.com: [HASH_1], [HASH_2], ...`

Copy the correct hash and add it to your list of pins.

### With `package:http`

```dart
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() async {
  final secureClient = IOClient(HttpSecurityPinningClient(
    ["e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY="], // github.com's SPKI hash
  ));

  try {
    final response = await secureClient.get(Uri.parse('https://github.com'));
    print('SUCCESS: ${response.statusCode}');
  } catch (e) {
    print('ERROR: $e');
  }
}
```

### With `package:dio`

```dart
import 'package:dio/dio.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() async {
  final dio = Dio();
  (dio.httpClientAdapter as IOHttpClientAdapter).onHttpClientCreate = (client) {
    return HttpSecurityPinningClient(
      ["e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY="], // github.com's SPKI hash
    );
  };

  try {
    final response = await dio.get('https://github.com');
    print('SUCCESS: ${response.statusCode}');
  } catch (e) {
    print('ERROR: $e');
  }
}
```

## Advanced Usage: Global Pinning

For a cleaner approach that applies pinning to all `HttpClient` requests in your app, you can use `HttpOverrides`. This is useful for ensuring all network traffic is secure without modifying every request call site.

1.  Create a custom `HttpOverrides` class:

```dart
import 'dart:io';
import 'package:http_security_pinning/http_security_pinning.dart';

class MyHttpOverrides extends HttpOverrides {
  final List<String> pins;
  MyHttpOverrides(this.pins);

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    // Note: Timeout and retry parameters can also be passed here
    return HttpSecurityPinningClient(pins);
  }
}
```

2.  Install it once in your `main()` function:

```dart
void main() {
  HttpOverrides.global = MyHttpOverrides([
    "e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=", // github.com's SPKI hash
  ]);

  runApp(MyApp());
}
```

Now, all standard `http.get()`, `dio.get()`, etc., calls will automatically use the pinning logic.

## Error Handling

This package throws specific exceptions to allow for fine-grained error handling.

- `NoValidPinsFoundException`: Thrown if the server's certificates are fetched successfully but none match the provided pins.
- `CertificateFetchException`: Thrown if there is a problem fetching the certificate chain from the server (e.g., a network error or timeout).

```dart
import 'package:http_security_pinning/exceptions.dart';

try {
  // Your request...
} on NoValidPinsFoundException catch (e) {
  print('Pinning validation failed for ${e.host}: ${e.message}');
} on CertificateFetchException catch (e) {
  print('Failed to fetch certificates: ${e.message}');
} catch (e) {
  print('A generic error occurred: $e');
}
```

## Additional Information

- **Repository**: Find the source code on [GitHub](https://github.com/CaoGiaHieu-dev/http_security_pinning.git).
- **Issue Tracker**: Report bugs and request features on the [issue tracker](https://github.com/CaoGiaHieu-dev/http_security_pinning.git/issues).