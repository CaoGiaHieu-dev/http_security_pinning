import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Uint8List _pemToDer(String pemContent) {
  final clean = pemContent
      .replaceAll('\r', '')
      .split('\n')
      .map((l) => l.trim())
      .where((line) =>
          line.isNotEmpty &&
          !line.startsWith('-----BEGIN') &&
          !line.startsWith('-----END'))
      .join();
  return base64.decode(clean);
}

/// Helper that binds a local HTTPS server serving [chainPath] with [keyPath].
Future<HttpServer> _startSecureServer(String chainPath, String keyPath) async {
  final ctx = SecurityContext()
    ..useCertificateChain(chainPath)
    ..usePrivateKey(keyPath);
  final server = await HttpServer.bindSecure('127.0.0.1', 0, ctx);
  server.listen((HttpRequest request) {
    request.response.statusCode = HttpStatus.ok;
    request.response.headers.contentType = ContentType.text;
    request.response.write('secure-response');
    request.response.close();
  });
  return server;
}

/// Fake fetcher that returns the certificate chain for localhost by reading
/// the fixture chain file.
class FixtureFetcher implements CertificateChainFetcher {
  final List<Uint8List> chain;

  FixtureFetcher(this.chain);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) async => chain;
}

void main() {
  const f = 'test/fixtures/';
  late Map<String, dynamic> groundTruthPins;
  late List<Uint8List> chainA1;
  late List<Uint8List> chainB;

  setUpAll(() {
    final jsonFile = File('${f}pins.json');
    groundTruthPins =
        json.decode(jsonFile.readAsStringSync()) as Map<String, dynamic>;

    final leafA1Der = _pemToDer(File('${f}server_a1.pem').readAsStringSync());
    final intCaDer =
        _pemToDer(File('${f}intermediate_ca.pem').readAsStringSync());
    final rootCaDer = _pemToDer(File('${f}root_ca.pem').readAsStringSync());
    final leafBDer = _pemToDer(File('${f}server_b.pem').readAsStringSync());

    chainA1 = [leafA1Der, intCaDer, rootCaDer];
    chainB = [leafBDer, intCaDer, rootCaDer];
  });

  group('HttpSecurityPinningClient Component Tests with Local HTTPS Server',
      () {
    late HttpServer server;
    late int port;

    setUp(() async {
      server = await _startSecureServer(
          '${f}server_a1_chain.pem', '${f}server_a.key');
      port = server.port;
    });

    tearDown(() async {
      await server.close(force: true);
    });

    test('isSupported returns true on native VM', () {
      expect(HttpSecurityPinningClient.isSupported, isTrue);
    });

    test('succeeds when pinned to leaf certificate', () async {
      final pin = groundTruthPins['server_a1'] as String;
      final service = PinningService(
        fetcher: FixtureFetcher(chainA1),
        cache: CertificateChainCache(),
      );

      final client = HttpSecurityPinningClient(
        [pin],
        pinningService: service,
      );

      final request =
          await client.getUrl(Uri.parse('https://localhost:$port/'));
      final response = await request.close();
      final body = await response.transform(utf8.decoder).join();

      expect(response.statusCode, HttpStatus.ok);
      expect(body, 'secure-response');
      client.close();
    });

    test('succeeds when pinned to intermediate CA', () async {
      final pin = groundTruthPins['intermediate_ca'] as String;
      final service = PinningService(
        fetcher: FixtureFetcher(chainA1),
        cache: CertificateChainCache(),
      );

      final client = HttpSecurityPinningClient(
        [pin],
        pinningService: service,
      );

      final request =
          await client.getUrl(Uri.parse('https://localhost:$port/'));
      final response = await request.close();
      expect(response.statusCode, HttpStatus.ok);
      client.close();
    });

    test('succeeds when pinned to root CA', () async {
      final pin = groundTruthPins['root_ca'] as String;
      final service = PinningService(
        fetcher: FixtureFetcher(chainA1),
        cache: CertificateChainCache(),
      );

      final client = HttpSecurityPinningClient(
        [pin],
        pinningService: service,
      );

      final request =
          await client.getUrl(Uri.parse('https://localhost:$port/'));
      final response = await request.close();
      expect(response.statusCode, HttpStatus.ok);
      client.close();
    });

    test('throws NoValidPinsFoundException on mismatched pin', () async {
      // Pin B does not match server A1
      final wrongPin = groundTruthPins['server_b'] as String;
      final service = PinningService(
        fetcher: FixtureFetcher(chainA1),
        cache: CertificateChainCache(),
      );

      final client = HttpSecurityPinningClient(
        [wrongPin],
        pinningService: service,
      );

      await expectLater(
        () => client.getUrl(Uri.parse('https://localhost:$port/')),
        throwsA(isA<NoValidPinsFoundException>()
            .having((e) => e.host, 'host', 'localhost')
            .having((e) => e.observedPins.isNotEmpty, 'observedPins', isTrue)),
      );
      client.close();
    });

    test(
        'refuses unencrypted http:// with InsecureConnectionException when pinned',
        () async {
      final pin = groundTruthPins['server_a1'] as String;
      final client = HttpSecurityPinningClient([pin]);

      await expectLater(
        () => client.getUrl(Uri.parse('http://localhost:$port/')),
        throwsA(isA<InsecureConnectionException>()),
      );
      client.close();
    });

    test('perHost policy allows unpinned host when configured', () async {
      final pin = groundTruthPins['server_a1'] as String;
      final service = PinningService(
        fetcher: FixtureFetcher(chainA1),
        cache: CertificateChainCache(),
      );

      final client = HttpSecurityPinningClient.perHost(
        {
          'other.domain.com': [pin],
        },
        allowUnpinnedHosts: true,
        pinningService: service,
      );

      // localhost has no pins, but unpinned is allowed -> calls raw client
      // Raw client handshake with untrusted local cert throws HandshakeException (normal TLS behavior)
      await expectLater(
        () => client.getUrl(Uri.parse('https://localhost:$port/')),
        throwsA(isA<HandshakeException>()),
      );
      client.close();
    });

    test(
        'perHost policy rejects unpinned host when allowUnpinnedHosts is false',
        () async {
      final pin = groundTruthPins['server_a1'] as String;
      final client = HttpSecurityPinningClient.perHost(
        {
          'other.domain.com': [pin],
        },
        allowUnpinnedHosts: false,
      );

      await expectLater(
        () => client.getUrl(Uri.parse('https://localhost:$port/')),
        throwsA(isA<UnpinnedHostException>()),
      );
      client.close();
    });

    group('badCertificateCallback behavior', () {
      test(
          'invokes badCertificateCallback on pin failure with PresentedCertificate',
          () async {
        final wrongPin = groundTruthPins['server_b'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [wrongPin],
          honorBadCertificateCallback: false, // Default: secure
          pinningService: service,
        );

        X509Certificate? receivedCert;
        String? receivedHost;
        int? receivedPort;

        client.badCertificateCallback = (cert, host, port) {
          receivedCert = cert;
          receivedHost = host;
          receivedPort = port;
          return true; // Tries to accept, but honorBadCertificateCallback is false!
        };

        await expectLater(
          () => client.getUrl(Uri.parse('https://localhost:$port/')),
          throwsA(isA<NoValidPinsFoundException>()),
        );

        expect(receivedCert, isNotNull);
        expect(receivedCert!.der, equals(chainA1.first));
        expect(receivedCert!.sha1.length, 20);
        expect(receivedCert!.pem, contains('-----BEGIN CERTIFICATE-----'));
        expect(receivedHost, 'localhost');
        expect(receivedPort, port);
        client.close();
      });

      test(
          'bypasses pinning when honorBadCertificateCallback is true and callback returns true',
          () async {
        final wrongPin = groundTruthPins['server_b'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [wrongPin],
          honorBadCertificateCallback: true, // Opt-in debug bypass
          pinningService: service,
        );

        bool callbackCalled = false;
        client.badCertificateCallback = (cert, host, port) {
          callbackCalled = true;
          return true; // Bypass accepted!
        };

        // When bypassed, raw client is used. Since raw client connects to self-signed local server,
        // it triggers the raw client's TLS badCertificateCallback.
        // With badCertificateCallback returning true, the request succeeds!
        final request =
            await client.getUrl(Uri.parse('https://localhost:$port/'));
        final response = await request.close();
        expect(response.statusCode, HttpStatus.ok);
        expect(callbackCalled, isTrue);
        client.close();
      });

      test(
          'does NOT invoke badCertificateCallback when pins match successfully',
          () async {
        final correctPin = groundTruthPins['server_a1'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [correctPin],
          pinningService: service,
        );

        bool callbackCalled = false;
        client.badCertificateCallback = (cert, host, port) {
          callbackCalled = true;
          return true;
        };

        final request =
            await client.getUrl(Uri.parse('https://localhost:$port/'));
        final response = await request.close();
        expect(response.statusCode, HttpStatus.ok);
        expect(callbackCalled, isFalse); // Never called on success
        client.close();
      });
    });

    group('HttpOverrides.global infinite recursion prevention', () {
      test(
          'does not cause StackOverflow when HttpOverrides.global is installed',
          () async {
        final pin = groundTruthPins['server_a1'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final originalOverrides = HttpOverrides.current;
        try {
          HttpOverrides.global = _TestOverrides(pin, service);

          // Standard HttpClient() call resolved through HttpOverrides.global
          final client = HttpClient();
          final request =
              await client.getUrl(Uri.parse('https://localhost:$port/'));
          final response = await request.close();
          expect(response.statusCode, HttpStatus.ok);
          client.close();
        } finally {
          HttpOverrides.global = originalOverrides;
        }
      });
    });

    group('Multi-host concurrency and connection pool', () {
      test('manages multiple hosts concurrently without closing delegates',
          () async {
        final server2 = await _startSecureServer(
            '${f}server_b_chain.pem', '${f}server_b.key');
        final port2 = server2.port;

        try {
          final pinA = groundTruthPins['server_a1'] as String;
          final pinB = groundTruthPins['server_b'] as String;

          final multiFetcher = _MultiHostFetcher({
            port: chainA1,
            port2: chainB,
          });

          final client = HttpSecurityPinningClient(
            [pinA, pinB],
            pinningService: PinningService(
              fetcher: multiFetcher,
              cache: CertificateChainCache(),
            ),
          );

          // Fire concurrent requests to both servers using the same client instance
          final req1Future =
              client.getUrl(Uri.parse('https://localhost:$port/'));
          final req2Future =
              client.getUrl(Uri.parse('https://localhost:$port2/'));

          final requests = await Future.wait([req1Future, req2Future]);
          final responses = await Future.wait(requests.map((r) => r.close()));

          expect(responses[0].statusCode, HttpStatus.ok);
          expect(responses[1].statusCode, HttpStatus.ok);

          // Subsequent requests to both servers still work (neither was prematurely closed)
          final req1Again =
              await client.getUrl(Uri.parse('https://localhost:$port/'));
          final res1Again = await req1Again.close();
          expect(res1Again.statusCode, HttpStatus.ok);

          client.close();
        } finally {
          await server2.close(force: true);
        }
      });
    });

    group('HttpClient delegations, properties, and lifecycle', () {
      test('throws StateError when used after close()', () async {
        final client = HttpSecurityPinningClient(
            ['e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=']);
        client.close();
        expect(
          () => client.getUrl(Uri.parse('https://localhost:$port/')),
          throwsA(isA<StateError>()),
        );
      });

      test(
          'throws InsecureConnectionException when requesting http:// scheme with pins',
          () async {
        final client = HttpSecurityPinningClient(
            ['e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=']);
        addTearDown(client.close);

        expect(
          () => client.getUrl(Uri.parse('http://localhost:$port/')),
          throwsA(isA<InsecureConnectionException>()),
        );
      });

      test('clearCache empties the shared certificate cache', () {
        CertificateChainCache.shared
            .getOrFetch('test:443', () async => [Uint8List(0)]);
        expect(CertificateChainCache.shared.contains('test:443'), isTrue);

        HttpSecurityPinningClient.clearCache();
        expect(CertificateChainCache.shared.contains('test:443'), isFalse);
      });

      test('getters and setters apply properties cleanly', () {
        final client = HttpSecurityPinningClient(
            ['e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=']);
        addTearDown(client.close);

        client.idleTimeout = const Duration(seconds: 30);
        expect(client.idleTimeout, const Duration(seconds: 30));

        client.connectionTimeout = const Duration(seconds: 5);
        expect(client.connectionTimeout, const Duration(seconds: 5));

        client.maxConnectionsPerHost = 10;
        expect(client.maxConnectionsPerHost, 10);

        client.autoUncompress = false;
        expect(client.autoUncompress, isFalse);

        client.userAgent = 'CustomAgent/1.0';
        expect(client.userAgent, 'CustomAgent/1.0');

        client.authenticate = (url, scheme, realm) async => true;
        client.connectionFactory =
            (uri, proxyHost, proxyPort) async => throw UnimplementedError();
        client.keyLog = (line) {};
        client.findProxy = (uri) => 'DIRECT';
        client.authenticateProxy = (host, port, scheme, realm) async => true;

        client.addCredentials(Uri.parse('https://example.com'), 'realm',
            HttpClientBasicCredentials('u', 'p'));
        client.addProxyCredentials(
            'proxy.com', 8080, 'realm', HttpClientBasicCredentials('u', 'p'));
      });

      test(
          'HTTP convenience methods (post, put, delete, head, patch) work when pinned',
          () async {
        final pin = groundTruthPins['server_a1'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [pin],
          pinningService: service,
        );
        addTearDown(client.close);

        final reqGet = await client.get('localhost', port, '/');
        final resGet = await reqGet.close();
        expect(resGet.statusCode, HttpStatus.ok);

        final reqPost = await client.post('localhost', port, '/');
        final resPost = await reqPost.close();
        expect(resPost.statusCode, HttpStatus.ok);

        final reqPostUrl =
            await client.postUrl(Uri.parse('https://localhost:$port/'));
        final resPostUrl = await reqPostUrl.close();
        expect(resPostUrl.statusCode, HttpStatus.ok);

        final reqPut = await client.put('localhost', port, '/');
        final resPut = await reqPut.close();
        expect(resPut.statusCode, HttpStatus.ok);

        final reqPutUrl =
            await client.putUrl(Uri.parse('https://localhost:$port/'));
        final resPutUrl = await reqPutUrl.close();
        expect(resPutUrl.statusCode, HttpStatus.ok);

        final reqDelete = await client.delete('localhost', port, '/');
        final resDelete = await reqDelete.close();
        expect(resDelete.statusCode, HttpStatus.ok);

        final reqDeleteUrl =
            await client.deleteUrl(Uri.parse('https://localhost:$port/'));
        final resDeleteUrl = await reqDeleteUrl.close();
        expect(resDeleteUrl.statusCode, HttpStatus.ok);

        final reqHead = await client.head('localhost', port, '/');
        final resHead = await reqHead.close();
        expect(resHead.statusCode, HttpStatus.ok);

        final reqHeadUrl =
            await client.headUrl(Uri.parse('https://localhost:$port/'));
        final resHeadUrl = await reqHeadUrl.close();
        expect(resHeadUrl.statusCode, HttpStatus.ok);

        final reqPatch = await client.patch('localhost', port, '/');
        final resPatch = await reqPatch.close();
        expect(resPatch.statusCode, HttpStatus.ok);

        final reqPatchUrl =
            await client.patchUrl(Uri.parse('https://localhost:$port/'));
        final resPatchUrl = await reqPatchUrl.close();
        expect(resPatchUrl.statusCode, HttpStatus.ok);
      });

      test('updates properties across existing pooled clients', () async {
        final pin = groundTruthPins['server_a1'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [pin],
          pinningService: service,
        );
        addTearDown(client.close);

        // Make a request first to instantiate a pooled client
        final req = await client.getUrl(Uri.parse('https://localhost:$port/'));
        await req.close();

        // Now mutate properties on already pooled clients
        client.idleTimeout = const Duration(seconds: 45);
        client.connectionTimeout = const Duration(seconds: 12);
        client.maxConnectionsPerHost = 8;
        client.autoUncompress = false;
        client.userAgent = 'PooledAgent/2.0';
        client.authenticate = (url, scheme, realm) async => true;
        client.connectionFactory =
            (uri, proxyHost, proxyPort) async => throw UnimplementedError();
        client.keyLog = (line) {};
        client.findProxy = (uri) => 'DIRECT';
        client.authenticateProxy = (host, port, scheme, realm) async => true;
        client.badCertificateCallback = (cert, host, port) => false;
        client.addCredentials(Uri.parse('https://localhost:$port'), 'realm',
            HttpClientBasicCredentials('u', 'p'));
        client.addProxyCredentials(
            'localhost', port, 'realm', HttpClientBasicCredentials('u', 'p'));
      });

      test('applies credentials and proxy credentials to newly created clients',
          () async {
        final pin = groundTruthPins['server_a1'] as String;
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [pin],
          pinningService: service,
        );
        addTearDown(client.close);

        client.addCredentials(Uri.parse('https://localhost:$port'), 'realm',
            HttpClientBasicCredentials('u', 'p'));
        client.addProxyCredentials(
            'localhost', port, 'realm', HttpClientBasicCredentials('u', 'p'));

        final req = await client.getUrl(Uri.parse('https://localhost:$port/'));
        final res = await req.close();
        expect(res.statusCode, HttpStatus.ok);
      });

      test(
          'safely catches exceptions thrown inside user badCertificateCallback',
          () async {
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [groundTruthPins['server_b'] as String],
          pinningService: service,
        );
        addTearDown(client.close);

        client.badCertificateCallback = (cert, host, port) {
          throw Exception('Exploding callback');
        };

        await expectLater(
          () => client.getUrl(Uri.parse('https://localhost:$port/')),
          throwsA(isA<NoValidPinsFoundException>()),
        );
      });

      test(
          'reuses bypass list for subsequent requests when honorBadCertificateCallback is true',
          () async {
        final service = PinningService(
          fetcher: FixtureFetcher(chainA1),
          cache: CertificateChainCache(),
        );

        final client = HttpSecurityPinningClient(
          [groundTruthPins['server_b'] as String],
          pinningService: service,
          honorBadCertificateCallback: true,
        );
        addTearDown(client.close);

        client.badCertificateCallback = (cert, host, port) => true;

        // First request triggers bypass logic
        final req1 = await client.getUrl(Uri.parse('https://localhost:$port/'));
        final res1 = await req1.close();
        expect(res1.statusCode, HttpStatus.ok);

        // Second request uses _bypassedHosts branch
        final req2 = await client.getUrl(Uri.parse('https://localhost:$port/'));
        final res2 = await req2.close();
        expect(res2.statusCode, HttpStatus.ok);
      });
    });
  });
}

class _TestOverrides extends HttpOverrides {
  final String pin;
  final PinningService service;
  _TestOverrides(this.pin, this.service);

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return HttpSecurityPinningClient(
      [pin],
      pinningService: service,
    );
  }
}

class _MultiHostFetcher implements CertificateChainFetcher {
  final Map<int, List<Uint8List>> chainsByPort;
  _MultiHostFetcher(this.chainsByPort);

  @override
  Future<List<Uint8List>> fetchChain(Uri url, Duration timeout) async {
    return chainsByPort[url.port] ?? [];
  }
}
