import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Active SPKI pins for github.com (leaf and intermediate CA).
  const githubLeafPin = '/wiL5vgOLgwED41WS0DNF8QiTBVR/P41Kd163tmFxK0=';
  const githubIntermediatePin = 'ZSagvDzjltLkewXEBuDxIzpW/dpVw1Juvvmd0hhkzdY=';
  const activePins = [githubLeafPin, githubIntermediatePin];

  // Dummy valid 32-byte Base64 pin that will NOT match github.com
  const nonMatchingPin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  group('HttpSecurityPinningClient Full Integration Tests', () {
    setUp(() {
      HttpSecurityPinningClient.clearCache();
    });

    testWidgets('1. should succeed with correct pin using http package', (
      WidgetTester tester,
    ) async {
      final secureClient = IOClient(
        HttpSecurityPinningClient(
          activePins,
          timeout: const Duration(seconds: 10),
          retryCount: 2,
        ),
      );

      final http.Response response = await secureClient.get(
        Uri.parse('https://github.com'),
      );
      expect(response.statusCode, 200);
      secureClient.close();
    });

    testWidgets('2. should succeed with correct pin using dio package', (
      WidgetTester tester,
    ) async {
      final dio = Dio();
      (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
        return HttpSecurityPinningClient(
          activePins,
          timeout: const Duration(seconds: 10),
          retryCount: 2,
        );
      };

      final response = await dio.get('https://github.com');
      expect(response.statusCode, 200);
      dio.close();
    });

    testWidgets(
      '3. should fail with incorrect pin and throw NoValidPinsFoundException',
      (WidgetTester tester) async {
        final secureClient = IOClient(
          HttpSecurityPinningClient([nonMatchingPin]),
        );

        await expectLater(
          () => secureClient.get(Uri.parse('https://github.com')),
          throwsA(isA<NoValidPinsFoundException>()),
        );
        secureClient.close();
      },
    );

    testWidgets(
      '4. should invoke badCertificateCallback with PresentedCertificate on pin failure',
      (WidgetTester tester) async {
        X509Certificate? receivedCert;
        String? receivedHost;
        int? receivedPort;

        final rawClient = HttpSecurityPinningClient(
          [nonMatchingPin],
          honorBadCertificateCallback: false, // Default fail-safe
        );
        rawClient.badCertificateCallback = (cert, host, port) {
          receivedCert = cert;
          receivedHost = host;
          receivedPort = port;
          return true; // Attempt to accept, but fail-safe mode prevents bypass
        };

        final secureClient = IOClient(rawClient);

        await expectLater(
          () => secureClient.get(Uri.parse('https://github.com')),
          throwsA(isA<NoValidPinsFoundException>()),
        );

        // Verify certificate inspection details
        expect(receivedCert, isNotNull);
        expect(receivedCert, isA<PresentedCertificate>());
        expect(receivedCert!.subject, contains('github.com'));
        expect(receivedCert!.pem, contains('-----BEGIN CERTIFICATE-----'));
        expect(receivedCert!.sha1.isNotEmpty, isTrue);
        expect(receivedCert!.der.isNotEmpty, isTrue);
        expect(receivedHost, 'github.com');
        expect(receivedPort, 443);

        secureClient.close();
      },
    );

    testWidgets(
      '5. should bypass pin failure when honorBadCertificateCallback is true and callback returns true',
      (WidgetTester tester) async {
        bool callbackFired = false;

        final rawClient = HttpSecurityPinningClient(
          [nonMatchingPin],
          honorBadCertificateCallback: true, // Opt-in debug bypass
        );
        rawClient.badCertificateCallback = (cert, host, port) {
          callbackFired = true;
          return true; // Bypass pin failure
        };

        final secureClient = IOClient(rawClient);

        final http.Response response = await secureClient.get(
          Uri.parse('https://github.com'),
        );
        expect(response.statusCode, 200);
        expect(callbackFired, isTrue);

        secureClient.close();
      },
    );

    testWidgets(
      '6. should strictly reject connection when honorBadCertificateCallback is false even if callback returns true',
      (WidgetTester tester) async {
        bool callbackFired = false;

        final rawClient = HttpSecurityPinningClient(
          [nonMatchingPin],
          honorBadCertificateCallback: false, // Strict mode
        );
        rawClient.badCertificateCallback = (cert, host, port) {
          callbackFired = true;
          return true; // Caller tried to accept
        };

        final secureClient = IOClient(rawClient);

        await expectLater(
          () => secureClient.get(Uri.parse('https://github.com')),
          throwsA(isA<NoValidPinsFoundException>()),
        );
        expect(callbackFired, isTrue);

        secureClient.close();
      },
    );

    testWidgets('7. should succeed with perHost policy and wildcard matching', (
      WidgetTester tester,
    ) async {
      final secureClient = IOClient(
        HttpSecurityPinningClient.perHost({
          '*.github.com': activePins,
          'github.com': activePins,
        }),
      );

      final http.Response response = await secureClient.get(
        Uri.parse('https://github.com'),
      );
      expect(response.statusCode, 200);

      secureClient.close();
    });

    testWidgets(
      '8. should succeed for unpinned host when allowUnpinnedHosts is true',
      (WidgetTester tester) async {
        final secureClient = IOClient(
          HttpSecurityPinningClient.perHost({
            'unrelated.host.com': [nonMatchingPin],
          }, allowUnpinnedHosts: true),
        );

        final http.Response response = await secureClient.get(
          Uri.parse('https://google.com'),
        );
        expect(response.statusCode, 200);

        secureClient.close();
      },
    );

    testWidgets(
      '9. should fail to connect to a bad certificate host (self-signed)',
      (WidgetTester tester) async {
        final secureClient = IOClient(HttpSecurityPinningClient([]));

        await expectLater(
          () => secureClient.get(Uri.parse('https://self-signed.badssl.com/')),
          throwsA(isA<HandshakeException>()),
        );

        secureClient.close();
      },
    );

    testWidgets(
      '10. should fail with short timeout and throw CertificateFetchException',
      (WidgetTester tester) async {
        final secureClient = IOClient(
          HttpSecurityPinningClient(
            activePins,
            timeout: const Duration(milliseconds: 1),
            retryCount: 1,
          ),
        );

        await expectLater(
          () => secureClient.get(Uri.parse('https://github.com')),
          throwsA(isA<CertificateFetchException>()),
        );

        secureClient.close();
      },
    );
  });
}
