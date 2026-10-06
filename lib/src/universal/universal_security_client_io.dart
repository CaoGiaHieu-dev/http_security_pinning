import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import '../client/client.dart';

/// Unified cross-platform security client factory.
class UniversalSecurityClient {
  /// Creates a unified [http.Client] that uses native TLS SPKI Pinning on Android/iOS/Desktop.
  static http.Client create({
    List<String>? spkiPins,
    List<int>? serverPublicKeyBytes,
    Duration timeout = const Duration(seconds: 10),
    int retryCount = 3,
    Duration retryDelay = const Duration(milliseconds: 200),
    bool honorBadCertificateCallback = false,
    Duration timestampTolerance = const Duration(minutes: 5),
  }) {
    return IOClient(
      HttpSecurityPinningClient(
        spkiPins ?? [],
        timeout: timeout,
        retryCount: retryCount,
        retryDelay: retryDelay,
        honorBadCertificateCallback: honorBadCertificateCallback,
      ),
    );
  }
}
