// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// End-to-end tests on a real Android or iOS device (they use the native
// probe). They need Internet access.
//
//   cd example && flutter test integration_test
//
// Pins of public hosts rotate, so every test first *discovers* the pins the
// host presents (exactly what an app developer does once, out of band) and
// then checks the behaviour of the client with them.

import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';
import 'package:integration_test/integration_test.dart';

/// A valid pin that matches no real key.
const _nonMatchingPin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const _otherNonMatchingPin = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=';

/// Returns the SPKI pins [url]'s server presents, leaf first.
Future<List<String>> _discoverPins(Uri url) async {
  final client = HttpSecurityPinningClient([_nonMatchingPin]);
  try {
    await (await client.getUrl(url)).close();
    throw StateError('The non-matching pin matched');
  } on NoValidPinsFoundException catch (e) {
    return e.observedPins;
  } finally {
    client.close(force: true);
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final github = Uri.parse('https://github.com');
  late List<String> githubPins;

  setUpAll(() async {
    HttpSecurityPinningClient.clearCache();
    githubPins = await _discoverPins(github);
  });

  setUp(HttpSecurityPinningClient.clearCache);

  testWidgets('the native probe returns the chain the platform exposes', (
    tester,
  ) async {
    expect(githubPins, isNotEmpty);
    if (Platform.isAndroid || Platform.isIOS) {
      // Leaf + at least one intermediate.
      expect(githubPins.length, greaterThanOrEqualTo(2));
    } else {
      // dart:io on desktop only exposes the leaf.
      expect(githubPins.length, 1);
    }
  });

  testWidgets('succeeds with the leaf pin using package:http', (tester) async {
    final client = IOClient(
      HttpSecurityPinningClient(
        [githubPins.first, _nonMatchingPin],
        timeout: const Duration(seconds: 10),
        retryCount: 2,
      ),
    );
    final response = await client.get(github);
    expect(response.statusCode, 200);
    client.close();
  });

  testWidgets('succeeds with an intermediate pin on mobile', (tester) async {
    if (!(Platform.isAndroid || Platform.isIOS)) return;
    final client = IOClient(
      HttpSecurityPinningClient([githubPins[1], _nonMatchingPin]),
    );
    expect((await client.get(github)).statusCode, 200);
    client.close();
  });

  testWidgets('succeeds using dio', (tester) async {
    final dio = Dio();
    (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () =>
        HttpSecurityPinningClient([githubPins.first, _nonMatchingPin]);
    final response = await dio.get<String>(github.toString());
    expect(response.statusCode, 200);
    dio.close(force: true);
  });

  testWidgets('fails with non-matching pins and reports the observed pins', (
    tester,
  ) async {
    X509Certificate? receivedCert;
    final raw =
        HttpSecurityPinningClient([_nonMatchingPin, _otherNonMatchingPin])
          ..badCertificateCallback = (cert, host, port) {
            receivedCert = cert;
            return true; // ignored: honorBadCertificateCallback is false
          };
    final client = IOClient(raw);
    await expectLater(
      client.get(github),
      throwsA(
        isA<NoValidPinsFoundException>().having(
          (e) => e.observedPins,
          'observedPins',
          githubPins,
        ),
      ),
    );
    expect(receivedCert, isA<PresentedCertificate>());
    expect(receivedCert!.subject, contains('github.com'));
    client.close();
  });

  testWidgets('the debug bypass applies to one request only', (tester) async {
    var calls = 0;
    final raw = HttpSecurityPinningClient(
      [_nonMatchingPin, _otherNonMatchingPin],
      honorBadCertificateCallback: true,
    )..badCertificateCallback = (cert, host, port) => ++calls == 1;
    final client = IOClient(raw);
    expect((await client.get(github)).statusCode, 200);
    await expectLater(
      client.get(github),
      throwsA(isA<NoValidPinsFoundException>()),
    );
    expect(calls, 2);
    client.close();
  });

  testWidgets('per-host policies refuse unpinned hosts by default', (
    tester,
  ) async {
    final client = IOClient(
      HttpSecurityPinningClient.perHost({
        'github.com': [githubPins.first, _nonMatchingPin],
      }),
    );
    expect((await client.get(github)).statusCode, 200);
    await expectLater(
      client.get(Uri.parse('https://example.com')),
      throwsA(isA<UnpinnedHostException>()),
    );
    await expectLater(
      client.get(Uri.parse('http://github.com')),
      throwsA(isA<InsecureConnectionException>()),
    );
    client.close();
  });

  testWidgets('allowUnpinnedHosts uses normal TLS for other hosts', (
    tester,
  ) async {
    final client = IOClient(
      HttpSecurityPinningClient.perHost({
        'unrelated.example': [_nonMatchingPin, _otherNonMatchingPin],
      }, allowUnpinnedHosts: true),
    );
    expect(
      (await client.get(Uri.parse('https://example.com'))).statusCode,
      200,
    );
    client.close();
  });

  testWidgets('a matching pin does not skip host name verification', (
    tester,
  ) async {
    final wrongHost = Uri.parse('https://wrong.host.badssl.com/');
    final pins = await _discoverPins(wrongHost);
    final client = IOClient(
      HttpSecurityPinningClient([...pins, _nonMatchingPin]),
    );
    await expectLater(
      client.get(wrongHost),
      throwsA(isA<HandshakeException>()),
    );
    client.close();
  });

  testWidgets('empty pin lists are rejected', (tester) async {
    expect(() => HttpSecurityPinningClient([]), throwsArgumentError);
    expect(() => UniversalSecurityClient.create(), throwsArgumentError);
  });

  testWidgets('a very short timeout fails with CertificateFetchException', (
    tester,
  ) async {
    final client = IOClient(
      HttpSecurityPinningClient(
        [githubPins.first, _nonMatchingPin],
        timeout: const Duration(milliseconds: 1),
        retryCount: 0,
      ),
    );
    await expectLater(
      client.get(github),
      throwsA(isA<CertificateFetchException>()),
    );
    client.close();
  });
}
