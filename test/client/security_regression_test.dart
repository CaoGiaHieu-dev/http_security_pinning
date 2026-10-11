// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Regression tests for the findings of the 1.2.2 security audit (dart:io).
// Each test reproduces an attack that used to succeed and asserts that it is
// now rejected.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

const _f = 'test/fixtures/';

Uint8List _pemToDer(String pem) => base64.decode(pem
    .replaceAll('\r', '')
    .split('\n')
    .map((l) => l.trim())
    .where((l) => l.isNotEmpty && !l.startsWith('-----'))
    .join());

class _FixtureFetcher implements CertificateChainFetcher {
  final List<Uint8List> chain;
  int calls = 0;
  _FixtureFetcher(this.chain);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) async {
    calls++;
    return chain;
  }
}

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

PinningService _realProbe() => PinningService(
      fetcher: const DartIoCertificateFetcher(),
      cache: CertificateChainCache(),
    );

void main() {
  final pins = json.decode(File('${_f}pins.json').readAsStringSync())
      as Map<String, dynamic>;
  final pinA = pins['server_a1'] as String;
  final pinB = pins['server_b'] as String;

  group('H-1 redirects are re-checked on every hop', () {
    test('a redirect from a pinned host to cleartext http is refused',
        () async {
      final seenByCleartext = <String, String>{};
      final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      plain.listen((req) {
        req.headers.forEach((k, v) => seenByCleartext[k] = v.join(','));
        req.response
          ..write('attacker-controlled-body')
          ..close();
      });
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        req.response
          ..statusCode = HttpStatus.found
          ..headers.set('location', 'http://localhost:${plain.port}/steal')
          ..close();
      });
      addTearDown(() => tls.close(force: true));
      addTearDown(() => plain.close(force: true));

      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB]
        },
        pinningService: _realProbe(),
      );
      final io = IOClient(client);
      addTearDown(io.close);

      await expectLater(
        io.get(Uri.parse('https://localhost:${tls.port}/'),
            headers: {'x-api-key': 'SECRET-123'}),
        throwsA(isA<InsecureConnectionException>()),
      );
      expect(seenByCleartext, isEmpty);
    });

    test('an https -> http downgrade is refused even to an allowed host',
        () async {
      var cleartextHits = 0;
      final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      plain.listen((req) {
        cleartextHits++;
        req.response.close();
      });
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        req.response
          ..statusCode = HttpStatus.movedPermanently
          ..headers.set('location', 'http://127.0.0.1:${plain.port}/')
          ..close();
      });
      addTearDown(() => tls.close(force: true));
      addTearDown(() => plain.close(force: true));

      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB]
        },
        allowUnpinnedHosts: true,
        pinningService: _realProbe(),
      );
      addTearDown(client.close);

      final request =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/'));
      await expectLater(
          request.close(), throwsA(isA<InsecureConnectionException>()));
      expect(cleartextHits, 0);
    });

    test('a redirect to a host forbidden by the policy is refused', () async {
      late HttpServer tls;
      tls = await _secureServer('${_f}server_a1_chain.pem', '${_f}server_a.key',
          (req) {
        if (req.uri.path == '/start') {
          req.response
            ..statusCode = HttpStatus.found
            ..headers.set('location', 'https://127.0.0.1:${tls.port}/other')
            ..close();
        } else {
          req.response
            ..write('served-for-${req.headers.host}')
            ..close();
        }
      });
      addTearDown(() => tls.close(force: true));

      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB]
        },
        pinningService: _realProbe(),
      );
      addTearDown(client.close);

      final request =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/start'));
      await expectLater(request.close(), throwsA(isA<UnpinnedHostException>()));
    });

    test('allowed redirects are followed, re-pinned and reported', () async {
      final seenMethods = <String>[];
      late HttpServer tls;
      tls = await _secureServer('${_f}server_a1_chain.pem', '${_f}server_a.key',
          (req) {
        seenMethods.add('${req.method} ${req.uri.path}');
        switch (req.uri.path) {
          case '/a':
            req.response
              ..statusCode = HttpStatus.seeOther
              ..headers.set('location', '/b')
              ..close();
          case '/b':
            req.response
              ..statusCode = HttpStatus.temporaryRedirect
              ..headers.set('location', 'https://localhost:${tls.port}/c')
              ..close();
          default:
            req.response
              ..write('final:${req.headers.value('x-api-key')}')
              ..close();
        }
      });
      addTearDown(() => tls.close(force: true));

      final fetcher = _FixtureFetcher([
        _pemToDer(File('${_f}server_a1.pem').readAsStringSync()),
      ]);
      final client = HttpSecurityPinningClient(
        [pinA, pinB],
        pinningService:
            PinningService(fetcher: fetcher, cache: CertificateChainCache()),
      );
      final io = IOClient(client);
      addTearDown(io.close);

      final response = await io.post(
        Uri.parse('https://localhost:${tls.port}/a'),
        headers: {'x-api-key': 'k'},
        body: 'payload',
      );
      expect(response.statusCode, 200);
      expect(response.body, 'final:k');
      expect(seenMethods, ['POST /a', 'GET /b', 'GET /c']);
    });

    test('maxRedirects is enforced and followRedirects=false is honoured',
        () async {
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        final n = int.parse(req.uri.path.substring(1));
        req.response
          ..statusCode = HttpStatus.found
          ..headers.set('location', '/${n + 1}')
          ..close();
      });
      addTearDown(() => tls.close(force: true));

      final client = HttpSecurityPinningClient(
        [pinA, pinB],
        pinningService: _realProbe(),
      );
      addTearDown(client.close);

      final limited =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/0'));
      limited.maxRedirects = 2;
      await expectLater(limited.close(), throwsA(isA<RedirectException>()));

      final manual =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/0'));
      manual.followRedirects = false;
      final response = await manual.close();
      expect(response.statusCode, HttpStatus.found);
      expect(response.isRedirect, isTrue);
      await response.drain<void>();

      // A manual redirect also goes through the pinning client.
      final next = await response.redirect();
      expect(next.redirects.single.location.path, '/1');
      await next.drain<void>();
    });
  });

  group('H-2 empty configurations fail closed', () {
    test('an empty pin list is rejected', () {
      expect(() => HttpSecurityPinningClient([]), throwsArgumentError);
      expect(
        () => HttpSecurityPinningClient.perHost({}),
        throwsArgumentError,
      );
      expect(
        () => HttpSecurityPinningClient.perHost({'a.com': []}),
        throwsArgumentError,
      );
    });

    test('UniversalSecurityClient requires pins on dart:io', () {
      expect(() => UniversalSecurityClient.create(), throwsArgumentError);
      expect(
        () => UniversalSecurityClient.create(spkiPins: const []),
        throwsArgumentError,
      );
      expect(
        () => UniversalSecurityClient.create(
          serverPublicKeys: [List.filled(32, 1)],
        ),
        throwsArgumentError,
      );
    });

    test('invalid timing arguments are rejected', () {
      expect(
        () => HttpSecurityPinningClient([pinA], timeout: Duration.zero),
        throwsArgumentError,
      );
      expect(
        () => HttpSecurityPinningClient([pinA], retryCount: -1),
        throwsArgumentError,
      );
      expect(
        () => HttpSecurityPinningClient([pinA],
            retryDelay: const Duration(milliseconds: -1)),
        throwsArgumentError,
      );
    });
  });

  group('M-7 the scheme is checked on every request', () {
    test('http:// after https:// to the same host:port is refused', () async {
      var requests = 0;
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        requests++;
        req.response
          ..write('pinned')
          ..close();
      });
      addTearDown(() => tls.close(force: true));

      final client = HttpSecurityPinningClient(
        [pinA, pinB],
        pinningService: PinningService(
          fetcher: _FixtureFetcher([
            _pemToDer(File('${_f}server_a1.pem').readAsStringSync()),
          ]),
          cache: CertificateChainCache(),
        ),
      );
      addTearDown(client.close);

      // A successful pinned request leaves a cached pinned delegate for
      // localhost:<port>.
      final ok = await (await client
              .getUrl(Uri.parse('https://localhost:${tls.port}/')))
          .close();
      expect(await ok.transform(utf8.decoder).join(), 'pinned');
      await expectLater(
        client.getUrl(Uri.parse('http://localhost:${tls.port}/')),
        throwsA(isA<InsecureConnectionException>()),
      );
      expect(requests, 1);
    });
  });

  group('M-3 badCertificateCallback bypass', () {
    late HttpServer server;
    setUp(() async {
      server = await _secureServer(
        '${_f}server_b_chain.pem',
        '${_f}server_b.key',
        (r) => r.response
          ..write('B')
          ..close(),
      );
    });
    tearDown(() => server.close(force: true));

    test('is decided per request and never sticky', () async {
      final answers = [true, false];
      var calls = 0;
      final client = HttpSecurityPinningClient(
        [pinA, pins['selfsigned'] as String],
        honorBadCertificateCallback: true,
        pinningService: _realProbe(),
      )..badCertificateCallback = (cert, host, port) => answers[calls++];
      addTearDown(client.close);

      // 1st request: pin mismatch, callback says yes -> one-shot bypass. The
      // test CA is not trusted by the system, so the raw client asks the
      // callback again for the handshake (answer: no).
      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${server.port}/')),
        throwsA(isA<HandshakeException>()),
      );
      expect(calls, 2);

      // A later request asks again instead of reusing a bypass list.
      answers
        ..clear()
        ..add(false);
      calls = 0;
      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${server.port}/')),
        throwsA(isA<NoValidPinsFoundException>()),
      );
      expect(calls, 1);
    });

    test('cannot override a pinned connection', () async {
      // The probe reports server A's (pinned) chain, but the real server
      // presents B: the pinned handshake fails and the callback's "true" is
      // ignored.
      var calls = 0;
      final client = HttpSecurityPinningClient(
        [pinA, pins['selfsigned'] as String],
        honorBadCertificateCallback: true,
        pinningService: PinningService(
          fetcher: _FixtureFetcher([
            _pemToDer(File('${_f}server_a1.pem').readAsStringSync()),
          ]),
          cache: CertificateChainCache(),
        ),
      )..badCertificateCallback = (cert, host, port) {
          calls++;
          return true;
        };
      addTearDown(client.close);

      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${server.port}/')),
        throwsA(isA<HandshakeException>()),
      );
      expect(calls, greaterThan(0));
    });
  });

  group('review findings', () {
    test('IO-2 a host with CR/LF never reaches the probe', () async {
      final fetcher = _FixtureFetcher(const []);
      final client = HttpSecurityPinningClient.perHost(
        {
          '*.example.com': [pinA, pinB]
        },
        pinningService:
            PinningService(fetcher: fetcher, cache: CertificateChainCache()),
      );
      addTearDown(client.close);
      await expectLater(
        client.getUrl(Uri.parse('https://evil%0D%0Ax.example.com/')),
        throwsArgumentError,
      );
      expect(fetcher.calls, 0);
    });

    test('IO-1 another spelling of a pinned IP literal is still pinned',
        () async {
      final fetcher = _FixtureFetcher([
        _pemToDer(File('${_f}server_a1.pem').readAsStringSync()),
      ]);
      final client = HttpSecurityPinningClient.perHost(
        {
          '127.0.0.1': [pinA, pinB]
        },
        allowUnpinnedHosts: true,
        pinningService:
            PinningService(fetcher: fetcher, cache: CertificateChainCache()),
      );
      addTearDown(client.close);
      // Nothing listens on port 1: the request fails, but only after the
      // policy matched and the probe ran.
      await expectLater(
          client.getUrl(Uri.parse('https://127.1:1/')), throwsA(anything));
      expect(fetcher.calls, 1);
    });

    test('IO-3 concurrent requests each get their own bypass decision',
        () async {
      final server = await _secureServer(
        '${_f}server_b_chain.pem',
        '${_f}server_b.key',
        (r) => r.response
          ..write('B')
          ..close(),
      );
      addTearDown(() => server.close(force: true));
      var pinDecisions = 0;
      final client = HttpSecurityPinningClient(
        [pinA, pins['selfsigned'] as String],
        honorBadCertificateCallback: true,
        pinningService: PinningService(
          fetcher: _FixtureFetcher([
            _pemToDer(File('${_f}server_b.pem').readAsStringSync()),
          ]),
          cache: CertificateChainCache(),
        ),
      )..badCertificateCallback = (cert, host, port) {
          // PresentedCertificate = a pin-mismatch decision; the platform
          // certificate = the bypass client's own handshake check.
          if (cert is PresentedCertificate) pinDecisions++;
          return true;
        };
      addTearDown(client.close);

      final url = Uri.parse('https://localhost:${server.port}/');
      final bodies = await Future.wait([
        for (var i = 0; i < 5; i++)
          client
              .getUrl(url)
              .then((r) => r.close())
              .then((r) => r.transform(utf8.decoder).join()),
      ]);
      expect(bodies, List.filled(5, 'B'));
      // Exactly one pin-mismatch decision per request.
      expect(pinDecisions, 5);
    });

    test('S-2 abort() reaches the redirect hop in flight', () async {
      final stalled = Completer<void>();
      final secondHopReached = Completer<void>();
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) async {
        if (req.uri.path == '/a') {
          req.response
            ..statusCode = HttpStatus.found
            ..headers.set('location', '/b')
            ..close();
        } else {
          secondHopReached.complete();
          await stalled.future; // never answers /b
          req.response.close();
        }
      });
      addTearDown(() async {
        if (!stalled.isCompleted) stalled.complete();
        await tls.close(force: true);
      });

      final client =
          HttpSecurityPinningClient([pinA, pinB], pinningService: _realProbe());
      addTearDown(() => client.close(force: true));
      final request =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/a'));
      final response = request.close();
      await secondHopReached.future;
      request.abort();
      await expectLater(
        response.timeout(const Duration(seconds: 5)),
        throwsA(isA<HttpException>()),
      );
    });

    test('S-1 a SecureSocket from connectionFactory is refused', () async {
      final legit = await _secureServer('${_f}server_a1_chain.pem',
          '${_f}server_a.key', (r) => r.response.close());
      addTearDown(() => legit.close(force: true));
      final client =
          HttpSecurityPinningClient([pinA, pinB], pinningService: _realProbe())
            ..connectionFactory = (uri, proxyHost, proxyPort) =>
                SecureSocket.startConnect('127.0.0.1', legit.port,
                    onBadCertificate: (_) => true);
      addTearDown(client.close);
      await expectLater(
        client.getUrl(Uri.parse('https://localhost:${legit.port}/')),
        throwsA(isA<HandshakeException>()
            .having((e) => e.message, 'message', contains('SecureSocket'))),
      );
    });
  });

  test('L-2 open() keeps the query string', () async {
    String? seenPath;
    String? seenQuery;
    final tls = await _secureServer(
        '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
      seenPath = req.uri.path;
      seenQuery = req.uri.query;
      req.response.close();
    });
    addTearDown(() => tls.close(force: true));

    final client =
        HttpSecurityPinningClient([pinA, pinB], pinningService: _realProbe());
    addTearDown(client.close);
    await (await client.get('localhost', tls.port, '/search?q=1#frag')).close();
    expect(seenPath, '/search');
    expect(seenQuery, 'q=1');
  });

  test('M-8 desktop pin failures explain the leaf-only limitation', () async {
    final tls = await _secureServer('${_f}server_a1_chain.pem',
        '${_f}server_a.key', (r) => r.response.close());
    addTearDown(() => tls.close(force: true));

    final client = HttpSecurityPinningClient(
      [pins['intermediate_ca'] as String, pins['root_ca'] as String],
      pinningService: _realProbe(),
    );
    addTearDown(client.close);
    await expectLater(
      client.getUrl(Uri.parse('https://localhost:${tls.port}/')),
      throwsA(isA<NoValidPinsFoundException>()
          .having((e) => e.leafOnly, 'leafOnly', isTrue)
          .having((e) => e.observedPins, 'observedPins', [pinA]).having(
              (e) => e.message, 'message', contains('leaf'))),
    );
  });

  test('the hostname is still verified when the pin matches', () async {
    // The trailing_dot leaf is only valid for "localhost.".
    final tls = await _secureServer(
      '${_f}trailing_dot_chain.pem',
      '${_f}trailing_dot.key',
      (r) => r.response.close(),
    );
    addTearDown(() => tls.close(force: true));
    final leafPin = base64.encode(SpkiHasher.sha256Digest(
        _pemToDer(File('${_f}trailing_dot_chain.pem').readAsStringSync())));

    final client = HttpSecurityPinningClient([leafPin, pinB],
        pinningService: _realProbe());
    addTearDown(client.close);
    await expectLater(
      client.getUrl(Uri.parse('https://127.0.0.1:${tls.port}/')),
      throwsA(isA<HandshakeException>()),
    );
  });

  group('review round 3', () {
    test('a host with invalid UTF-8 is an ArgumentError, not a FormatException',
        () async {
      final client =
          HttpSecurityPinningClient([pinA, pinB], pinningService: _realProbe());
      addTearDown(client.close);
      await expectLater(client.getUrl(Uri.parse('https://a%FFb.example/')),
          throwsArgumentError);
    });

    test('close(force: true) also stops requests on retired delegates',
        () async {
      // The first connection reaches server A (pinned key) and streams
      // forever; every later connection reaches server B (key not pinned),
      // whose TLS failure retires the delegate used by the first request.
      final a = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        req.response.bufferOutput = false;
        final timer = Timer.periodic(
            const Duration(milliseconds: 50), (_) => req.response.write('.'));
        req.response.done.whenComplete(timer.cancel).ignore();
      });
      final b = await _secureServer('${_f}server_b_chain.pem',
          '${_f}server_b.key', (req) => req.response.close());
      var connections = 0;
      final front = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      front.listen((client) async {
        final upstream = await Socket.connect(
            InternetAddress.loopbackIPv4, connections++ == 0 ? a.port : b.port);
        client.cast<List<int>>().pipe(upstream).ignore();
        upstream.cast<List<int>>().pipe(client).ignore();
      });
      addTearDown(() async {
        await front.close();
        await a.close(force: true);
        await b.close(force: true);
      });

      final client = HttpSecurityPinningClient(
        [pinA, pins['selfsigned'] as String],
        pinningService: PinningService(
          fetcher: _FixtureFetcher([
            _pemToDer(File('${_f}server_a1.pem').readAsStringSync()),
          ]),
          cache: CertificateChainCache(),
        ),
      );
      final url = Uri.parse('https://localhost:${front.port}/');
      final streaming = await (await client.getUrl(url)).close();
      final firstChunk = Completer<void>();
      final ended = Completer<void>();
      streaming.listen((_) {
        if (!firstChunk.isCompleted) firstChunk.complete();
      }, onError: (_) {
        if (!ended.isCompleted) ended.complete();
      }, onDone: () {
        if (!ended.isCompleted) ended.complete();
      });
      await firstChunk.future;

      // Server B: handshake failure, the pinned delegate is retired.
      await expectLater(client.getUrl(url), throwsA(isA<HandshakeException>()));

      client.close(force: true);
      await ended.future.timeout(const Duration(seconds: 5));
    });
  });

  group('review round 2', () {
    test('a huge crafted host is rejected without blocking the isolate', () {
      final host =
          String.fromCharCodes(List.generate(32000, (i) => 0x4e00 + i % 20000));
      final stopwatch = Stopwatch()..start();
      final normalized = HostNormalizer.normalize(host);
      expect(HostNormalizer.isValid(normalized), isFalse);
      expect(stopwatch.elapsedMilliseconds, lessThan(500));
      expect(
          HostNormalizer.isValid(HostNormalizer.normalize('${'a' * 64}.com')),
          isFalse);
    });

    test('an invalid Location raises a RedirectException', () async {
      final tls = await _secureServer(
          '${_f}server_a1_chain.pem', '${_f}server_a.key', (req) {
        req.response
          ..statusCode = HttpStatus.found
          ..headers.set(
              'location',
              switch (req.uri.path) {
                '/bad-host' => 'https://evil%0d%0a.example/',
                '/bad-utf8' => 'https://a%FFb.example/',
                _ => 'https://[::1:/',
              })
          ..close();
      });
      addTearDown(() => tls.close(force: true));
      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB]
        },
        allowUnpinnedHosts: true,
        pinningService: _realProbe(),
      );
      addTearDown(client.close);
      for (final path in ['/bad-host', '/bad-utf8', '/bad-uri']) {
        final request = await client
            .getUrl(Uri.parse('https://localhost:${tls.port}$path'));
        await expectLater(request.close(), throwsA(isA<RedirectException>()),
            reason: path);
      }
    });

    test('abort() wins over a redirect hop that is still being probed',
        () async {
      late HttpServer tls;
      tls = await _secureServer('${_f}server_a1_chain.pem', '${_f}server_a.key',
          (req) {
        req.response
          ..statusCode = HttpStatus.found
          ..headers.set('location', 'https://other.localhost:${tls.port}/')
          ..close();
      });
      addTearDown(() => tls.close(force: true));
      final probeStarted = Completer<void>();
      final neverAnswers = Completer<List<Uint8List>>();
      final client = HttpSecurityPinningClient.perHost(
        {
          'localhost': [pinA, pinB],
          'other.localhost': [pinA, pinB],
        },
        pinningService: PinningService(
          fetcher: _RoutingFetcher({
            'localhost': Future.value(
                [_pemToDer(File('${_f}server_a1.pem').readAsStringSync())]),
            'other.localhost': neverAnswers.future,
          }, onFetch: (host) {
            if (host == 'other.localhost') probeStarted.complete();
          }),
          cache: CertificateChainCache(),
        ),
      );
      addTearDown(() => client.close(force: true));
      final request =
          await client.getUrl(Uri.parse('https://localhost:${tls.port}/'));
      final response = request.close();
      await probeStarted.future;
      request.abort();
      await expectLater(response.timeout(const Duration(seconds: 2)),
          throwsA(isA<HttpException>()));
    });

    test('a TLS failure does not cancel other requests to the same host',
        () async {
      // The cached chain is stale (key A) while the server already presents
      // key B; both keys are pinned.
      final tls = await _secureServer(
        '${_f}server_b_chain.pem',
        '${_f}server_b.key',
        (r) => r.response
          ..write('ok')
          ..close(),
      );
      addTearDown(() => tls.close(force: true));
      final chains = [
        [_pemToDer(File('${_f}server_a1.pem').readAsStringSync())],
        [_pemToDer(File('${_f}server_b.pem').readAsStringSync())],
      ];
      var fetches = 0;
      final client = HttpSecurityPinningClient(
        [pinA, pinB],
        pinningService: PinningService(
          fetcher: _CallbackFetcher(
              () async => chains[(fetches++).clamp(0, chains.length - 1)]),
          cache: CertificateChainCache(),
        ),
      )..maxConnectionsPerHost = 1;
      addTearDown(client.close);
      final url = Uri.parse('https://localhost:${tls.port}/');
      final bodies = await Future.wait([
        for (var i = 0; i < 4; i++)
          client
              .getUrl(url)
              .then((r) => r.close())
              .then((r) => r.transform(utf8.decoder).join()),
      ]);
      expect(bodies, List.filled(4, 'ok'));
    });
  });

  test('close() during a pending probe does not leak a usable delegate',
      () async {
    final gate = Completer<List<Uint8List>>();
    final client = HttpSecurityPinningClient(
      [pinA, pinB],
      pinningService: PinningService(
        fetcher: _GatedFetcher(gate.future),
        cache: CertificateChainCache(),
      ),
    );
    final pending = client.getUrl(Uri.parse('https://localhost:1/'));
    client.close();
    gate.complete([_pemToDer(File('${_f}server_a1.pem').readAsStringSync())]);
    await expectLater(pending, throwsStateError);
  });
}

class _RoutingFetcher implements CertificateChainFetcher {
  final Map<String, Future<List<Uint8List>>> byHost;
  final void Function(String host) onFetch;
  _RoutingFetcher(this.byHost, {required this.onFetch});

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) {
    onFetch(url.host);
    return byHost[url.host]!;
  }
}

class _CallbackFetcher implements CertificateChainFetcher {
  final Future<List<Uint8List>> Function() fetch;
  _CallbackFetcher(this.fetch);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) => fetch();
}

class _GatedFetcher implements CertificateChainFetcher {
  final Future<List<Uint8List>> result;
  _GatedFetcher(this.result);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) => result;
}
