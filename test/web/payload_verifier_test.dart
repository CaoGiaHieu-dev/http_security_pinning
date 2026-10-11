// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  final url = Uri.parse('https://api.example.com/users/42?expand=true');
  const nonce = 'AAECAwQFBgcICQoLDA0ODw';
  const created = 1760169600000;
  final body = utf8.encode('{"id":42}');

  late ResponseSigner signer;
  late ResponseSigner nextSigner;
  late List<int> publicKey;
  late List<int> nextPublicKey;

  setUpAll(() async {
    signer = await ResponseSigner.fromSeed(List.generate(32, (i) => i));
    nextSigner = await ResponseSigner.fromSeed(List.generate(32, (i) => 99));
    publicKey = await signer.publicKeyBytes();
    nextPublicKey = await nextSigner.publicKeyBytes();
  });

  Future<Map<String, String>> signedHeaders({
    ResponseSigner? using,
    String method = 'GET',
    Uri? target,
    int status = 200,
    String n = nonce,
    String contentType = 'application/json',
    List<int>? bytes,
    int createdMs = created,
  }) async =>
      {
        'content-type': contentType,
        ...await (using ?? signer).sign(
          method: method,
          url: target ?? url,
          statusCode: status,
          nonce: n,
          contentType: contentType,
          bodyBytes: bytes ?? body,
          createdMs: createdMs,
        ),
      };

  Future<void> verify(
    Map<String, String> headers, {
    PayloadVerifier? verifier,
    String method = 'GET',
    Uri? target,
    int status = 200,
    String n = nonce,
    List<int>? bytes,
    int now = created,
  }) =>
      (verifier ?? PayloadVerifier(publicKeys: [publicKey])).verify(
        method: method,
        url: target ?? url,
        statusCode: status,
        nonce: n,
        headers: headers,
        bodyBytes: bytes ?? body,
        clientNowMs: now,
      );

  group('SignatureBase', () {
    test('matches the published test vector (README, Node.js example)',
        () async {
      expect(base64.encode(publicKey),
          'A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=');
      final headers = await signedHeaders();
      expect(
        headers['x-hsp-signature'],
        'lqUamjCnsQgg1W1/HZmLh9Ew25fyPhoF75EH32Kk/J/Var13xKU7vTTByb//BzsrZlB91P/P1RMy9I+JEMpjDw==',
      );
      expect(
        utf8.decode(SignatureBase.build(
          method: 'get',
          url: url,
          statusCode: 200,
          nonce: nonce,
          createdMs: created,
          contentType: ' application/json ',
          bodyBytes: body,
        )),
        'hsp-sig-v2\n'
        '@method: GET\n'
        '@scheme: https\n'
        '@authority: api.example.com\n'
        '@request-target: /users/42?expand=true\n'
        '@status: 200\n'
        '@nonce: AAECAwQFBgcICQoLDA0ODw\n'
        '@created: 1760169600000\n'
        'content-type: application/json\n'
        '@body-sha256: F7TbBk4X9IeOORF35spiO3mJEfNAFLyeeJIJk9fdJ60=',
      );
    });

    test('normalizes authority and request target', () {
      expect(
          SignatureBase.authorityOf(Uri.parse('https://API.Example.com.:443')),
          'api.example.com');
      expect(SignatureBase.authorityOf(Uri.parse('https://bücher.de:8443/')),
          'xn--bcher-kva.de:8443');
      expect(SignatureBase.authorityOf(Uri.parse('http://[::1]:80/')), '[::1]');
      expect(SignatureBase.requestTargetOf(Uri.parse('https://a.com')), '/');
      expect(
          SignatureBase.requestTargetOf(Uri.parse('https://a.com/p?')), '/p?');
      expect(SignatureBase.requestTargetOf(Uri.parse('https://a.com/p?q=1#f')),
          '/p?q=1');
    });

    test('rejects line breaks inside components', () {
      expect(
        () => SignatureBase.build(
          method: 'GET',
          url: url,
          statusCode: 200,
          nonce: 'a\nb',
          createdMs: created,
          contentType: '',
          bodyBytes: const [],
        ),
        throwsA(isA<MalformedSecurityHeaderException>()),
      );
    });
  });

  group('PayloadVerifier', () {
    test('accepts a valid signature', () async {
      await verify(await signedHeaders());
    });

    test('rejects a tampered body', () async {
      await expectLater(
        verify(await signedHeaders(), bytes: utf8.encode('{"id":43}')),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('W1 bytes cannot be moved between the nonce and the body', () async {
      // Signed: nonce "N", body "NOT_AUTHORIZED;AUTHORIZED".
      final headers = await signedHeaders(
          n: 'N', bytes: utf8.encode('NOT_AUTHORIZED;AUTHORIZED'));
      await expectLater(
        verify(headers, n: 'NOT_AUTHORIZED;', bytes: utf8.encode('AUTHORIZED')),
        throwsA(isA<SignatureVerificationException>()),
      );
      await expectLater(
        verify(headers,
            n: 'N', bytes: utf8.encode('NOT_AUTHORIZED;AUTHORIZED!')),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('W2 a response is bound to method, URL, status, type and nonce',
        () async {
      final headers = await signedHeaders();
      final attempts = <Future<void> Function()>[
        () => verify(headers, method: 'POST'),
        () => verify(headers,
            target: Uri.parse('https://api.example.com/users/43?expand=true')),
        () => verify(headers,
            target: Uri.parse('https://evil.example.net/users/42?expand=true')),
        () => verify(headers, status: 201),
        () => verify({...headers, 'content-type': 'text/html'}),
        () => verify(headers, n: 'another-request-nonce'),
        () => verify(headers,
            target: Uri.parse('http://api.example.com/users/42?expand=true')),
      ];
      for (final attempt in attempts) {
        await expectLater(
            attempt(), throwsA(isA<SignatureVerificationException>()));
      }
    });

    test('W3 signatures outside the time window are rejected both ways',
        () async {
      final headers = await signedHeaders();
      const minute = 60 * 1000;
      await expectLater(verify(headers, now: created + 6 * minute),
          throwsA(isA<ReplayAttackException>()));
      await expectLater(verify(headers, now: created - 6 * minute),
          throwsA(isA<ReplayAttackException>()));
      await verify(headers, now: created + 4 * minute);
      // The check can be disabled; the nonce still binds the response.
      await verify(
        headers,
        verifier:
            PayloadVerifier(publicKeys: [publicKey], timestampTolerance: null),
        now: created + 600 * minute,
      );
    });

    test('supports several keys for rotation', () async {
      final verifier = PayloadVerifier(publicKeys: [publicKey, nextPublicKey]);
      await verify(await signedHeaders(), verifier: verifier);
      await verify(await signedHeaders(using: nextSigner), verifier: verifier);
      await expectLater(
        verify(await signedHeaders(using: nextSigner)),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('W6/W9 bad key or signature lengths fail with typed errors', () async {
      expect(() => PayloadVerifier(publicKeys: [List.filled(31, 1)]),
          throwsArgumentError);
      expect(() => PayloadVerifier(publicKeys: const []), throwsArgumentError);
      final headers = await signedHeaders();
      for (final bad in ['AAAA', base64.encode(List.filled(65, 1)), '%%%']) {
        await expectLater(
          verify({...headers, 'x-hsp-signature': bad}),
          throwsA(isA<SignatureVerificationException>()),
        );
      }
    });

    test('reports missing and malformed headers', () async {
      final headers = await signedHeaders();
      await expectLater(
        verify({...headers}..remove('x-hsp-signature')),
        throwsA(isA<MissingSecurityHeaderException>()),
      );
      await expectLater(
        verify({...headers}..remove('x-hsp-created')),
        throwsA(isA<MissingSecurityHeaderException>()),
      );
      for (final bad in ['yesterday', '+1760169600000', '0x1', '-1']) {
        await expectLater(
          verify({...headers, 'x-hsp-created': bad}),
          throwsA(isA<MalformedSecurityHeaderException>()),
          reason: bad,
        );
      }
      await expectLater(
        verify(headers, n: '   '),
        throwsA(isA<MalformedSecurityHeaderException>()),
      );
    });

    test('header names are case-insensitive and keys accept base64url',
        () async {
      final headers = await signedHeaders();
      final upper = {
        for (final e in headers.entries) e.key.toUpperCase(): e.value,
      };
      final verifier = PayloadVerifier.fromBase64([
        base64Url.encode(publicKey).replaceAll('=', ''),
      ]);
      await verify(upper, verifier: verifier);
    });

    test('every web exception is a CertificatePinningException', () {
      expect(const SignatureVerificationException(),
          isA<CertificatePinningException>());
      expect(MissingSecurityHeaderException('x'),
          isA<CertificatePinningException>());
    });
  });
}
