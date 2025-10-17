import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // SPKI hash for github.com. This may need to be updated if the certificate changes.
  const githubPin = 'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=';

  group('HttpSecurityPinningClient Integration Tests', () {
    testWidgets('should succeed with correct pin', (WidgetTester tester) async {
      // Arrange
      final secureClient = IOClient(HttpSecurityPinningClient(
        [githubPin],
        // Using new constructor with default timeout and retries
        timeout: const Duration(seconds: 10),
        retryCount: 2,
      ));

      // Act & Assert
      try {
        final http.Response response =
            await secureClient.get(Uri.parse('https://github.com'));
        expect(response.statusCode, 200);
      } catch (e) {
        fail('Test failed: Should have connected successfully, but threw: $e');
      }
    });

    testWidgets('should fail with incorrect pin', (WidgetTester tester) async {
      // Arrange
      final secureClient = IOClient(
          HttpSecurityPinningClient(['dGVzdA=='])); // Valid Base64, but incorrect pin

      // Act & Assert
      expect(
        () async => await secureClient.get(Uri.parse('https://github.com')),
        throwsA(isA<NoValidPinsFoundException>()),
      );
    });

    testWidgets('should succeed without any pins', (WidgetTester tester) async {
      // Arrange
      final secureClient = IOClient(HttpSecurityPinningClient([]));

      // Act & Assert
      try {
        final http.Response response =
            await secureClient.get(Uri.parse('https://google.com'));
        expect(response.statusCode, 200);
      } catch (e) {
        fail(
            'Test failed: Should have connected successfully without pins, but threw: $e');
      }
    });

    testWidgets('should fail to connect to a bad certificate host',
        (WidgetTester tester) async {
      // Arrange
      final secureClient = IOClient(HttpSecurityPinningClient([]));

      // Act & Assert
      expect(
        () async => await secureClient
            .get(Uri.parse('https://self-signed.badssl.com/')),
        throwsA(isA<HandshakeException>()),
      );
    });

    testWidgets('should fail with a short timeout', (WidgetTester tester) async {
      // Arrange
      HttpSecurityPinningClient.clearCache(); // Clear cache to ensure a network request is made
      final secureClient = IOClient(HttpSecurityPinningClient(
        [githubPin], // Pin is correct, but timeout is too short
        timeout: const Duration(milliseconds: 1),
        retryCount: 1, // Allow one retry
      ));

      // Act & Assert
      expect(
        () async => await secureClient.get(Uri.parse('https://github.com')),
        throwsA(isA<CertificateFetchException>()),
      );
    });
  });
}
