// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

const _f = 'test/fixtures/';

/// A minimal HTTP CONNECT proxy that records the tunnels it opens.
class _ConnectProxy {
  final ServerSocket _server;
  final List<String> tunnels = [];
  final List<String?> authorizations = [];

  /// When set, every CONNECT is answered with this status line and closed.
  final String? refuseWith;

  _ConnectProxy._(this._server, {this.refuseWith}) {
    _server.listen(_handle);
  }

  static Future<_ConnectProxy> start({String? refuseWith}) async =>
      _ConnectProxy._(await ServerSocket.bind(InternetAddress.loopbackIPv4, 0),
          refuseWith: refuseWith);

  int get port => _server.port;

  void _handle(Socket client) {
    final buffer = <int>[];
    late StreamSubscription<List<int>> sub;
    sub = client.listen((data) async {
      buffer.addAll(data);
      final text = latin1.decode(buffer);
      final end = text.indexOf('\r\n\r\n');
      if (end == -1) return;
      sub.pause();
      final lines = text.substring(0, end).split('\r\n');
      final target = lines.first.split(' ')[1];
      tunnels.add(target);
      authorizations.add(lines
          .where((l) => l.toLowerCase().startsWith('proxy-authorization:'))
          .map((l) => l.substring(l.indexOf(':') + 1).trim())
          .firstOrNull);
      final refusal = refuseWith;
      if (refusal != null) {
        client.add(latin1.encode('$refusal\r\n\r\n'));
        await client.flush();
        client.destroy();
        return;
      }
      final hostPort = target.split(':');
      final upstream =
          await Socket.connect('127.0.0.1', int.parse(hostPort.last));
      client.add(latin1.encode('HTTP/1.1 200 Connection established\r\n\r\n'));
      final rest = buffer.sublist(end + 4);
      if (rest.isNotEmpty) upstream.add(rest);
      upstream.listen(client.add,
          onDone: client.destroy, onError: (_) => client.destroy());
      sub
        ..onData(upstream.add)
        ..onDone(upstream.destroy)
        ..resume();
    }, onError: (_) => client.destroy());
  }

  Future<void> close() => _server.close();
}

void main() {
  group('ProxyDirective', () {
    test('parses PROXY directives and ignores DIRECT', () {
      expect(ProxyDirective.parse('DIRECT'), isNull);
      final p = ProxyDirective.parse('PROXY proxy.local:3128; DIRECT')!;
      expect(p.host, 'proxy.local');
      expect(p.port, 3128);
      expect(p.authorization, isNull);

      final auth = ProxyDirective.parse('PROXY user:pa:ss@10.0.0.1:8080')!;
      expect(auth.host, '10.0.0.1');
      expect(auth.userInfo, 'user:pa:ss');
      expect(auth.authorization,
          'Basic ${base64.encode(utf8.encode('user:pa:ss'))}');

      expect(ProxyDirective.parse('PROXY onlyhost')!.port, 1080);
      final v6 = ProxyDirective.parse('PROXY [::1]:9000')!;
      expect(v6.host, '::1');
      expect(v6.toFindProxyString(), 'PROXY [::1]:9000');
    });
  });

  test('L-4 the desktop probe uses the same proxy as the request', () async {
    final pins = json.decode(File('${_f}pins.json').readAsStringSync())
        as Map<String, dynamic>;
    final ctx = SecurityContext()
      ..useCertificateChain('${_f}server_a1_chain.pem')
      ..usePrivateKey('${_f}server_a.key');
    final server =
        await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, ctx);
    server.listen((r) => r.response
      ..write('via-proxy')
      ..close());
    final proxy = await _ConnectProxy.start();
    addTearDown(() => server.close(force: true));
    addTearDown(proxy.close);

    final client = HttpSecurityPinningClient(
      [pins['server_a1'] as String, pins['server_b'] as String],
      pinningService: PinningService(
        fetcher: const DartIoCertificateFetcher(),
        cache: CertificateChainCache(),
      ),
    )..findProxy = (_) => 'PROXY 127.0.0.1:${proxy.port}';
    addTearDown(client.close);

    final response = await (await client
            .getUrl(Uri.parse('https://localhost:${server.port}/')))
        .close();
    expect(await response.transform(utf8.decoder).join(), 'via-proxy');
    // One tunnel for the probe, one for the real request.
    expect(proxy.tunnels, List.filled(2, 'localhost:${server.port}'));
  });

  group('fetchChainThroughProxy', () {
    late HttpServer server;
    late Uint8List leaf;

    setUp(() async {
      final ctx = SecurityContext()
        ..useCertificateChain('${_f}server_a1_chain.pem')
        ..usePrivateKey('${_f}server_a.key');
      server =
          await HttpServer.bindSecure(InternetAddress.loopbackIPv4, 0, ctx);
      server.listen((r) => r.response.close());
      final pem = File('${_f}server_a1.pem').readAsStringSync();
      leaf = base64.decode(pem
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && !l.startsWith('-----'))
          .join());
    });
    tearDown(() => server.close(force: true));

    test('returns the leaf certificate on every platform', () async {
      // The server sends leaf + intermediate; dart:io's bad-certificate
      // callback may report the intermediate on some platforms, the peer
      // certificate is always the leaf.
      final proxy = await _ConnectProxy.start();
      addTearDown(proxy.close);
      final chain =
          await const DartIoCertificateFetcher().fetchChainThroughProxy(
        Uri.parse('https://localhost:${server.port}/'),
        const Duration(seconds: 5),
        ProxyDirective.parse('PROXY user:secret@127.0.0.1:${proxy.port}')!,
      );
      expect(chain.single, leaf);
      expect(proxy.authorizations.single,
          'Basic ${base64.encode(utf8.encode('user:secret'))}');
    });

    test('a refused tunnel is a connection failure', () async {
      final proxy = await _ConnectProxy.start(
          refuseWith: 'HTTP/1.1 407 Proxy Authentication Required');
      addTearDown(proxy.close);
      await expectLater(
        const DartIoCertificateFetcher().fetchChainThroughProxy(
          Uri.parse('https://localhost:${server.port}/'),
          const Duration(seconds: 5),
          ProxyDirective('127.0.0.1', proxy.port),
        ),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'CONNECTION_FAILED')
            .having((e) => e.message, 'message', contains('407'))),
      );
    });
  });

  test('a proxied probe fails cleanly when the proxy is unreachable', () async {
    await expectLater(
      const DartIoCertificateFetcher().fetchChainThroughProxy(
        Uri.parse('https://localhost:1/'),
        const Duration(seconds: 2),
        const ProxyDirective('127.0.0.1', 1),
      ),
      throwsA(isA<CertificateFetchException>().having(
          (e) => e.code, 'code', isIn(['CONNECTION_FAILED', 'TIMEOUT']))),
    );
  });
}
