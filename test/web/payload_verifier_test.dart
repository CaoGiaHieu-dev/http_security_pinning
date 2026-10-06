import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('PayloadVerifier Web Tests', () {
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

    Future<String> signData({
      required List<int> bodyBytes,
      required String timestampStr,
      String? nonce,
    }) async {
      final dataToSign = <int>[
        ...utf8.encode(timestampStr),
        if (nonce != null) ...utf8.encode(nonce),
        ...bodyBytes,
      ];
      final signature = await algorithm.sign(dataToSign, keyPair: keyPair);
      return base64.encode(signature.bytes);
    }

    test('successfully verifies valid signature and timestamp', () async {
      final verifier = PayloadVerifier(
        pinnedPublicKeyBytes: publicKeyBytes,
        timestampTolerance: const Duration(minutes: 5),
      );

      final body = utf8.encode('{"message": "secure content"}');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final tsStr = nowMs.toString();
      final sigBase64 = await signData(bodyBytes: body, timestampStr: tsStr);

      final headers = {
        'x-server-signature': sigBase64,
        'x-signature-timestamp': tsStr,
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers, clientNowMs: nowMs),
        completes,
      );
    });

    test('throws SignatureVerificationException when body is tampered',
        () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);

      final body = utf8.encode('{"status": "ok"}');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final tsStr = nowMs.toString();
      final sigBase64 = await signData(bodyBytes: body, timestampStr: tsStr);

      final headers = {
        'x-server-signature': sigBase64,
        'x-signature-timestamp': tsStr,
      };

      final tamperedBody = utf8.encode('{"status": "tampered"}');

      await expectLater(
        verifier.verify(
          bodyBytes: tamperedBody,
          headers: headers,
          clientNowMs: nowMs,
        ),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('throws SignatureVerificationException when signature is forged',
        () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);

      final body = utf8.encode('{"status": "ok"}');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final tsStr = nowMs.toString();

      // Sign with a DIFFERENT key pair
      final attackerKeyPair = await algorithm.newKeyPair();
      final attackerSignature = await algorithm.sign(
        [...utf8.encode(tsStr), ...body],
        keyPair: attackerKeyPair,
      );

      final headers = {
        'x-server-signature': base64.encode(attackerSignature.bytes),
        'x-signature-timestamp': tsStr,
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers, clientNowMs: nowMs),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test(
        'throws MissingSecurityHeaderException when signature header is missing',
        () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);
      final body = utf8.encode('test');
      final headers = {'x-signature-timestamp': '123456789'};

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers),
        throwsA(isA<MissingSecurityHeaderException>()),
      );
    });

    test(
        'throws MissingSecurityHeaderException when timestamp header is missing',
        () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);
      final body = utf8.encode('test');
      final headers = {'x-server-signature': 'AAAA'};

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers),
        throwsA(isA<MissingSecurityHeaderException>()),
      );
    });

    test(
        'throws MalformedSecurityHeaderException when timestamp is non-numeric',
        () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);
      final body = utf8.encode('test');
      final headers = {
        'x-server-signature': 'AAAA',
        'x-signature-timestamp': 'invalid-timestamp',
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers),
        throwsA(isA<MalformedSecurityHeaderException>()),
      );
    });

    test('throws ReplayAttackException when timestamp is older than tolerance',
        () async {
      final verifier = PayloadVerifier(
        pinnedPublicKeyBytes: publicKeyBytes,
        timestampTolerance: const Duration(minutes: 5),
      );

      final body = utf8.encode('test');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      // 10 minutes in the past
      final oldMs = nowMs - const Duration(minutes: 10).inMilliseconds;
      final tsStr = oldMs.toString();
      final sigBase64 = await signData(bodyBytes: body, timestampStr: tsStr);

      final headers = {
        'x-server-signature': sigBase64,
        'x-signature-timestamp': tsStr,
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers, clientNowMs: nowMs),
        throwsA(isA<ReplayAttackException>()),
      );
    });

    test('supports case-insensitive header lookup', () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);

      final body = utf8.encode('case test');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final tsStr = nowMs.toString();
      final sigBase64 = await signData(bodyBytes: body, timestampStr: tsStr);

      final headers = {
        'X-SERVER-SIGNATURE': sigBase64,
        'X-SIGNATURE-TIMESTAMP': tsStr,
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers, clientNowMs: nowMs),
        completes,
      );
    });

    test('verifies with optional nonce included', () async {
      final verifier = PayloadVerifier(pinnedPublicKeyBytes: publicKeyBytes);

      final body = utf8.encode('nonce test');
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      final tsStr = nowMs.toString();
      const nonce = 'unique-nonce-1234';
      final sigBase64 = await signData(
        bodyBytes: body,
        timestampStr: tsStr,
        nonce: nonce,
      );

      final headers = {
        'x-server-signature': sigBase64,
        'x-signature-timestamp': tsStr,
        'x-signature-nonce': nonce,
      };

      await expectLater(
        verifier.verify(bodyBytes: body, headers: headers, clientNowMs: nowMs),
        completes,
      );
    });
  });
}
