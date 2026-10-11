// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Regression tests for the 1.2.2 audit: attacks by a certificate that the
// *system* trust store accepts but whose key is not pinned. Kept in its own
// file because it modifies SecurityContext.defaultContext for the isolate.

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

const _f = 'test/fixtures/';

Future<HttpServer> _secureServer(
  String chain,
  String key,
  void Function(HttpRequest) handler, {
  InternetAddress? address,
}) async {
  final ctx = SecurityContext()
    ..useCertificateChain(chain)
    ..usePrivateKey(key);
  final server = await HttpServer.bindSecure(
      address ?? InternetAddress.loopbackIPv4, 0, ctx);
  server.listen(handler);
  return server;
}

Future<String> _body(HttpClientResponse response) =>
    response.transform(utf8.decoder).join();

PinningService _realProbe() => PinningService(
      fetcher: const DartIoCertificateFetcher(),
      cache: CertificateChainCache(),
    );

void main() {
  final pins = json.decode(File('${_f}pins.json').readAsStringSync())
      as Map<String, dynamic>;
  final pinA = pins['server_a1'] as String;
  final pinB = pins['server_b'] as String;

  group('trust-store bypasses (attacker cert trusted by the system)', () {
    setUpAll(() {
      // Simulates a mis-issuing / user-installed CA trusted by the system.
      SecurityContext.defaultContext
        ..setTrustedCertificates('${_f}root_ca.pem')
        ..setTrustedCertificates('${_f}trailing_dot_ca.pem');
    });

    test('L-1 a trailing-dot host name is still pinned', () async {
      final server = await _secureServer(
        '${_f}trailing_dot_chain.pem',
        '${_f}trailing_dot.key',
        (r) => r.response
          ..write('ATTACKER')
          ..close(),
      );
      addTearDown(() => server.close(force: true));

      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB]
        },
        allowUnpinnedHosts: true,
        pinningService: _realProbe(),
      );
      addTearDown(client.close);

      await expectLater(
        client.getUrl(Uri.parse('https://localhost.:${server.port}/')),
        throwsA(isA<NoValidPinsFoundException>()),
      );
      await expectLater(
        client.getUrl(Uri.parse('https://LOCALHOST.:${server.port}/')),
        throwsA(isA<NoValidPinsFoundException>()),
      );
    });

    test('M-1 connectionFactory cannot route around the pinned context',
        () async {
      final legit = await _secureServer(
        '${_f}server_a1_chain.pem',
        '${_f}server_a.key',
        (r) => r.response
          ..write('LEGIT')
          ..close(),
      );
      final attacker = await _secureServer(
        '${_f}server_b_chain.pem',
        '${_f}server_b.key',
        (r) => r.response
          ..write('ATTACKER')
          ..close(),
      );
      addTearDown(() => legit.close(force: true));
      addTearDown(() => attacker.close(force: true));

      // Only server A's key is pinned here.
      final client = HttpSecurityPinningClient(
        [pinA, pins['root_ca'] as String],
        pinningService: _realProbe(),
      );
      addTearDown(client.close);

      // 1. A factory doing its own system-trust TLS to the attacker.
      client.connectionFactory = (uri, proxyHost, proxyPort) =>
          SecureSocket.startConnect('127.0.0.1', attacker.port);
      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${legit.port}/')),
        throwsA(isA<HandshakeException>()),
      );

      // 2. A factory returning a plain socket to the attacker: the client
      //    secures it with the pinned context, so the handshake fails.
      client.connectionFactory = (uri, proxyHost, proxyPort) =>
          Socket.startConnect('127.0.0.1', attacker.port);
      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${legit.port}/')),
        throwsA(isA<HandshakeException>()),
      );

      // 3. A plain socket to the legitimate server works.
      client.connectionFactory = (uri, proxyHost, proxyPort) =>
          Socket.startConnect('127.0.0.1', legit.port);
      final response = await (await client
              .getUrl(Uri.parse('https://localhost:${legit.port}/')))
          .close();
      expect(await _body(response), 'LEGIT');
    });
  });
}
