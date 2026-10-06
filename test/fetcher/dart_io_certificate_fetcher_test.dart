import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Future<HttpServer> _startSecureServer(String certPath, String keyPath) async {
  final context = SecurityContext()
    ..useCertificateChain(certPath)
    ..usePrivateKey(keyPath);

  final server = await HttpServer.bindSecure(
    InternetAddress.loopbackIPv4,
    0,
    context,
  );
  server.listen((HttpRequest request) {
    request.response.write('ok');
    request.response.close();
  });
  return server;
}

void main() {
  const f = 'test/fixtures/';

  group('DartIoCertificateFetcher', () {
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

    test('successfully fetches leaf certificate DER from secure server',
        () async {
      const fetcher = DartIoCertificateFetcher();
      final url = Uri.parse('https://localhost:$port');

      final chain = await fetcher.fetchChain(url, const Duration(seconds: 5));
      expect(chain, isNotEmpty);
      expect(chain.first, isA<Uint8List>());
      expect(chain.first.length, greaterThan(100));
    });

    test(
        'throws CertificateFetchException on connection refused to unused port',
        () async {
      const fetcher = DartIoCertificateFetcher();
      // Unused port
      final unusedSocket =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final unusedPort = unusedSocket.port;
      await unusedSocket.close();

      final url = Uri.parse('https://localhost:$unusedPort');
      expect(
        () => fetcher.fetchChain(url, const Duration(seconds: 2)),
        throwsA(isA<CertificateFetchException>().having(
            (e) => e.code, 'code', anyOf('CONNECTION_FAILED', 'TIMEOUT'))),
      );
    });

    test('throws CertificateFetchException with TIMEOUT on short timeout',
        () async {
      const fetcher = DartIoCertificateFetcher();
      // Binding a raw TCP socket that never completes TLS handshake
      final hangingServer =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => hangingServer.close());

      final url = Uri.parse('https://localhost:${hangingServer.port}');
      expect(
        () => fetcher.fetchChain(url, const Duration(milliseconds: 50)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'TIMEOUT')),
      );
    });

    test('throws CertificateFetchException on TLS handshake failure', () async {
      const fetcher = DartIoCertificateFetcher();
      final plainServer =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      plainServer.listen((socket) {
        socket.add([1, 2, 3, 4, 5]);
        socket.close();
      });
      addTearDown(() => plainServer.close());

      final url = Uri.parse('https://localhost:${plainServer.port}');
      expect(
        () => fetcher.fetchChain(url, const Duration(seconds: 2)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'CONNECTION_FAILED')),
      );
    });
  });
}
