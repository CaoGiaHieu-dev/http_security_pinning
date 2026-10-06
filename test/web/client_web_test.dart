import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:http_security_pinning/src/client/client_web.dart';
import 'package:http_security_pinning/src/web/exceptions.dart';

void main() {
  group('HttpSecurityPinningClient Web Implementation Tests', () {
    late Ed25519 algorithm;
    late SimpleKeyPair keyPair;
    late SimplePublicKey publicKey;
    late List<int> publicKeyBytes;

    setUp(() async {
      algorithm = Ed25519();
      keyPair = await algorithm.newKeyPair();
      publicKey = await keyPair.extractPublicKey();
      publicKeyBytes = publicKey.bytes;
    });

    Future<String> sign(List<int> body, String ts) async {
      final sig = await algorithm.sign(
        [...utf8.encode(ts), ...body],
        keyPair: keyPair,
      );
      return base64.encode(sig.bytes);
    }

    test('isSupported reports true on web', () {
      expect(HttpSecurityPinningClient.isSupported, isTrue);
    });

    test('passes through requests when no serverPublicKeyBytes is provided',
        () async {
      final mockInner = MockClient((request) async {
        return http.Response('plain response', 200);
      });

      final client = HttpSecurityPinningClient(
        ['dummyPin'],
        innerClient: mockInner,
      );

      final response = await client.get(Uri.parse('https://example.com/api'));
      expect(response.statusCode, 200);
      expect(response.body, 'plain response');
      client.close();
    });

    test(
        'successfully verifies response when valid signature header is present',
        () async {
      const bodyText = '{"status": "ok"}';
      final bodyBytes = utf8.encode(bodyText);
      final ts = DateTime.now().millisecondsSinceEpoch.toString();
      final sig = await sign(bodyBytes, ts);

      final mockInner = MockClient((request) async {
        return http.Response(
          bodyText,
          200,
          headers: {
            'x-server-signature': sig,
            'x-signature-timestamp': ts,
          },
        );
      });

      final client = HttpSecurityPinningClient(
        ['pin'],
        serverPublicKeyBytes: publicKeyBytes,
        innerClient: mockInner,
      );

      final response = await client.get(Uri.parse('https://example.com/data'));
      expect(response.statusCode, 200);
      expect(response.body, bodyText);
      client.close();
    });

    test('throws SignatureVerificationException when signature is invalid',
        () async {
      const bodyText = 'tampered';
      final ts = DateTime.now().millisecondsSinceEpoch.toString();

      final mockInner = MockClient((request) async {
        return http.Response(
          bodyText,
          200,
          headers: {
            'x-server-signature': 'invalid-base64-signature==',
            'x-signature-timestamp': ts,
          },
        );
      });

      final client = HttpSecurityPinningClient(
        ['pin'],
        serverPublicKeyBytes: publicKeyBytes,
        innerClient: mockInner,
      );

      await expectLater(
        () => client.get(Uri.parse('https://example.com/data')),
        throwsA(isA<SignatureVerificationException>()),
      );
      client.close();
    });

    test('invokes badCertificateCallback and supports debug bypass', () async {
      const bodyText = 'bad signature';
      final ts = DateTime.now().millisecondsSinceEpoch.toString();
      bool callbackInvoked = false;

      final mockInner = MockClient((request) async {
        return http.Response(
          bodyText,
          200,
          headers: {
            'x-server-signature': 'invalid==',
            'x-signature-timestamp': ts,
          },
        );
      });

      final client = HttpSecurityPinningClient(
        ['pin'],
        serverPublicKeyBytes: publicKeyBytes,
        innerClient: mockInner,
        honorBadCertificateCallback: true, // Opt-in debug bypass
      );

      client.badCertificateCallback = (error, host, port) {
        callbackInvoked = true;
        expect(host, 'example.com');
        return true; // Bypass
      };

      final response = await client.get(Uri.parse('https://example.com/data'));
      expect(response.statusCode, 200);
      expect(callbackInvoked, isTrue);
      expect(response.body, bodyText);
      client.close();
    });

    test('perHost factory initializes web client properly', () async {
      final mockInner = MockClient((request) async {
        return http.Response('perHost response', 200);
      });

      final client = HttpSecurityPinningClient.perHost(
        {
          'example.com': ['pin1', 'pin2']
        },
        innerClient: mockInner,
      );

      final response = await client.get(Uri.parse('https://example.com'));
      expect(response.statusCode, 200);
      client.close();
    });
  });
}
