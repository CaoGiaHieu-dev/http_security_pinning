// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests of the Flutter Web client. It only depends on package:http, so it
// runs on the VM with a mocked transport.

import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:http_security_pinning/src/client/client_web.dart';
import 'package:http_security_pinning/src/core/exceptions.dart';
import 'package:http_security_pinning/src/universal/universal_security_client_web.dart';
import 'package:http_security_pinning/src/web/exceptions.dart';
import 'package:http_security_pinning/src/web/response_signer.dart';

const _pin = '6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=';

/// A response that reports a final URL, as BrowserClient does after a
/// redirect.
class _ResponseWithUrl extends http.StreamedResponse
    implements http.BaseResponseWithUrl {
  @override
  final Uri url;
  _ResponseWithUrl(super.stream, super.statusCode,
      {required this.url, super.headers, super.request});
}

/// A transport returning whatever [handler] builds, unchanged.
class _FakeClient extends http.BaseClient {
  final Future<http.StreamedResponse> Function(http.BaseRequest) handler;
  _FakeClient(this.handler);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.finalize();
    return handler(request);
  }
}

void main() {
  late ResponseSigner signer;
  late ResponseSigner otherSigner;
  late List<int> key;
  late List<int> otherKey;

  setUpAll(() async {
    signer = await ResponseSigner.fromSeed(List.filled(32, 7));
    otherSigner = await ResponseSigner.fromSeed(List.filled(32, 8));
    key = await signer.publicKeyBytes();
    otherKey = await otherSigner.publicKeyBytes();
  });

  /// The response a signing server returns for [request].
  Future<http.Response> signedResponse(
    http.BaseRequest request,
    String body, {
    int status = 200,
    ResponseSigner? using,
    Uri? signAs,
  }) async {
    final bytes = utf8.encode(body);
    final headers = await (using ?? signer).sign(
      method: request.method,
      url: signAs ?? request.url,
      statusCode: status,
      nonce: request.headers['x-hsp-nonce'] ?? '',
      contentType: 'text/plain',
      bodyBytes: bytes,
    );
    return http.Response.bytes(bytes, status,
        headers: {...headers, 'content-type': 'text/plain'});
  }

  /// A server that signs `body` for whatever request it receives.
  MockClient signingServer(
    String body, {
    int status = 200,
    ResponseSigner? using,
    Uri? signAs,
    void Function(http.Request request)? onRequest,
  }) =>
      MockClient((request) async {
        onRequest?.call(request);
        return signedResponse(request, body,
            status: status, using: using, signAs: signAs);
      });

  group('construction', () {
    test('isSupported is false: browsers cannot pin TLS', () {
      expect(HttpSecurityPinningClient.isSupported, isFalse);
    });

    test('H-3 a key is required unless explicitly opted out', () {
      expect(() => HttpSecurityPinningClient([_pin]), throwsArgumentError);
      expect(
        () => HttpSecurityPinningClient([_pin], serverPublicKeys: const []),
        throwsArgumentError,
      );
      expect(
          () => HttpSecurityPinningClient.perHost({
                'a.com': [_pin]
              }),
          throwsArgumentError);
      expect(() => UniversalSecurityClient.create(spkiPins: [_pin]),
          throwsArgumentError);
      HttpSecurityPinningClient([_pin], allowUnverifiedResponses: true).close();
    });

    test('pins are validated even though browsers cannot use them', () {
      expect(
        () => HttpSecurityPinningClient(['not a pin'], serverPublicKeys: [key]),
        throwsA(isA<InvalidPinException>()),
      );
    });

    test('W9 key and argument validation happens at construction', () {
      expect(
        () => HttpSecurityPinningClient([],
            serverPublicKeys: [List.filled(31, 0)]),
        throwsArgumentError,
      );
      expect(
        () => HttpSecurityPinningClient([],
            serverPublicKeys: [key], timeout: Duration.zero),
        throwsArgumentError,
      );
      expect(
        () => HttpSecurityPinningClient([],
            serverPublicKeys: [key], maxResponseBytes: 0),
        throwsArgumentError,
      );
    });
  });

  group('verification', () {
    test('sends a fresh nonce and returns verified responses', () async {
      final nonces = <String>[];
      final client = HttpSecurityPinningClient(
        [_pin],
        serverPublicKeys: [key],
        innerClient: signingServer('hello',
            onRequest: (r) => nonces.add(r.headers['x-hsp-nonce']!)),
      );
      addTearDown(client.close);

      final r1 = await client.get(Uri.parse('https://api.example.com/a'));
      final r2 = await client.get(Uri.parse('https://api.example.com/a'));
      expect(r1.body, 'hello');
      expect(r2.body, 'hello');
      expect(nonces, hasLength(2));
      expect(nonces[0], isNot(nonces[1]));
      expect(nonces[0].length, greaterThanOrEqualTo(22));
    });

    test('W2 a response signed for another URL is rejected', () async {
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient: signingServer('{"role":"admin"}',
            signAs: Uri.parse('https://api.example.com/users/mallory')),
      );
      addTearDown(client.close);
      await expectLater(
        client.get(Uri.parse('https://api.example.com/users/bob')),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('a replayed response (signed for an earlier nonce) is rejected',
        () async {
      http.Response? captured;
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient: MockClient((request) async {
          final replay = captured;
          if (replay != null) return replay;
          final first = await signedResponse(request, 'balance: 100');
          captured = first;
          return first;
        }),
      );
      addTearDown(client.close);
      final url = Uri.parse('https://api.example.com/balance');
      await client.get(url);
      await expectLater(
          client.get(url), throwsA(isA<SignatureVerificationException>()));
    });

    test('an unsigned or wrongly signed response is rejected', () async {
      final unsigned = HttpSecurityPinningClient([],
          serverPublicKeys: [key],
          innerClient: MockClient((_) async => http.Response('attacker', 200)));
      addTearDown(unsigned.close);
      await expectLater(unsigned.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<MissingSecurityHeaderException>()));

      final wrongKey = HttpSecurityPinningClient([],
          serverPublicKeys: [key],
          innerClient: signingServer('x', using: otherSigner));
      addTearDown(wrongKey.close);
      await expectLater(wrongKey.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<SignatureVerificationException>()));
    });

    /// A transport that "redirects": the response reports [finalUrl], and is
    /// genuinely signed by the server for that final URL.
    http.Client redirectingTo(Uri finalUrl, {ResponseSigner? using}) =>
        _FakeClient((request) async {
          final bytes = utf8.encode('{"status":"ok"}');
          final headers = await (using ?? signer).sign(
            method: request.method,
            url: finalUrl,
            statusCode: 200,
            nonce: request.headers['x-hsp-nonce']!,
            contentType: '',
            bodyBytes: bytes,
          );
          return _ResponseWithUrl(Stream.value(bytes), 200,
              url: finalUrl, headers: headers, request: request);
        });

    test('W-2 a redirect to another endpoint of the same host is refused',
        () async {
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient:
            redirectingTo(Uri.parse('https://api.example.com/api/echo')),
      );
      addTearDown(client.close);
      await expectLater(
        client.post(Uri.parse('https://api.example.com/api/transfer/confirm')),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('W-1 a redirect to a host without keys cannot skip verification',
        () async {
      final client = HttpSecurityPinningClient.perHost(
        {},
        allowUnpinnedHosts: true,
        serverPublicKeysByHost: {
          'api.example.com': [key],
        },
        innerClient: _FakeClient((request) async => _ResponseWithUrl(
              Stream.value(utf8.encode('{"iban":"ATTACKER"}')),
              200,
              url: Uri.parse('https://evil.attacker.net/x'),
              request: request,
            )),
      );
      addTearDown(client.close);
      await expectLater(
        client.get(Uri.parse('https://api.example.com/payee')),
        throwsA(isA<SignatureVerificationException>()),
      );
    });

    test('an unchanged final URL is accepted', () async {
      final url = Uri.parse('https://api.example.com/item');
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient: redirectingTo(url),
      );
      addTearDown(client.close);
      final response = await client.send(http.Request('GET', url));
      expect(await response.stream.bytesToString(), '{"status":"ok"}');
      expect((response as http.BaseResponseWithUrl).url, url);
    });
  });

  group('W5 badCertificateCallback', () {
    test('accepts a single response only, and is asked every time', () async {
      final answers = [true, false];
      final errors = <Object>[];
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        honorBadCertificateCallback: true,
        innerClient: MockClient((_) async => http.Response('unsigned', 200)),
      )..badCertificateCallback = (error, host, port) {
          errors.add(error);
          return answers.removeAt(0);
        };
      addTearDown(client.close);

      final url = Uri.parse('https://api.example.com/a');
      expect((await client.get(url)).body, 'unsigned');
      await expectLater(
          client.get(url), throwsA(isA<MissingSecurityHeaderException>()));
      expect(errors, hasLength(2));
    });

    test('is only notified when honorBadCertificateCallback is false',
        () async {
      var calls = 0;
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient: MockClient((_) async => http.Response('unsigned', 200)),
      )..badCertificateCallback = (error, host, port) {
          calls++;
          return true;
        };
      addTearDown(client.close);
      await expectLater(client.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<MissingSecurityHeaderException>()));
      expect(calls, 1);
    });
  });

  group('W6 retries', () {
    test('idempotent requests are rebuilt and retried after network errors',
        () async {
      var calls = 0;
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        retryCount: 2,
        retryDelay: Duration.zero,
        innerClient: MockClient((request) async {
          if (++calls < 3) throw http.ClientException('connection reset');
          return signedResponse(request, 'ok');
        }),
      );
      addTearDown(client.close);
      final response = await client.get(Uri.parse('https://api.example.com/'));
      expect(response.body, 'ok');
      expect(calls, 3);
    });

    test('non-idempotent requests and verification failures are not retried',
        () async {
      var calls = 0;
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        retryDelay: Duration.zero,
        innerClient: MockClient((request) async {
          calls++;
          if (request.method == 'POST') {
            throw http.ClientException('connection reset');
          }
          return http.Response('unsigned', 200);
        }),
      );
      addTearDown(client.close);
      await expectLater(client.post(Uri.parse('https://api.example.com/')),
          throwsA(isA<http.ClientException>()));
      expect(calls, 1);
      await expectLater(client.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<MissingSecurityHeaderException>()));
      expect(calls, 2);
    });
  });

  group('W8 limits', () {
    test('the timeout also covers the response body', () async {
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        retryCount: 0,
        timeout: const Duration(milliseconds: 100),
        innerClient: MockClient.streaming((request, _) async {
          final never = StreamController<List<int>>();
          return http.StreamedResponse(never.stream, 200, request: request);
        }),
      );
      addTearDown(client.close);
      await expectLater(client.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<TimeoutException>()));
    });

    test('bodies larger than maxResponseBytes are refused', () async {
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        maxResponseBytes: 4,
        innerClient: signingServer('too long'),
      );
      addTearDown(client.close);
      await expectLater(client.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<ResponseTooLargeException>()));
    });
  });

  group('W10 perHost', () {
    test('uses the keys of each host and refuses unknown hosts', () async {
      final client = HttpSecurityPinningClient.perHost(
        {
          'a.example.com': [_pin]
        },
        serverPublicKeysByHost: {
          'a.example.com': [key],
          '*.b.example.com': [otherKey],
        },
        innerClient: MockClient((request) async {
          final s = request.url.host == 'a.example.com' ? signer : otherSigner;
          return signedResponse(request, 'from ${request.url.host}', using: s);
        }),
      );
      addTearDown(client.close);
      expect((await client.get(Uri.parse('https://a.example.com/'))).body,
          'from a.example.com');
      expect((await client.get(Uri.parse('https://x.b.example.com/'))).body,
          'from x.b.example.com');
      await expectLater(client.get(Uri.parse('https://c.example.com/')),
          throwsA(isA<UnpinnedHostException>()));
    });

    test('a Unicode look-alike of a keyed host never passes unverified',
        () async {
      final client = HttpSecurityPinningClient.perHost(
        {},
        allowUnpinnedHosts: true,
        serverPublicKeysByHost: {
          'api.example.com': [key],
        },
        innerClient: MockClient((_) async => http.Response('unsigned', 200)),
      );
      addTearDown(client.close);
      for (final host in ['api\u3002example.com', 'ａｐｉ.example.com']) {
        await expectLater(client.get(Uri.parse('https://$host/')),
            throwsA(isA<UnpinnedHostException>()),
            reason: host);
      }
    });

    test("a quote in the query is signed the way browsers send it", () async {
      final client = HttpSecurityPinningClient(
        [],
        serverPublicKeys: [key],
        innerClient: MockClient((request) async {
          // The server sees the browser's encoding of the URL.
          final onTheWire =
              Uri.parse(request.url.toString().replaceAll("'", '%27'));
          return signedResponse(request, 'quoted', signAs: onTheWire);
        }),
      );
      addTearDown(client.close);
      expect(
          (await client.get(Uri.parse("https://api.example.com/s?q=it's")))
              .body,
          'quoted');
    });

    test('allowUnverifiedResponses only exempts hosts without keys', () async {
      final client = HttpSecurityPinningClient.perHost(
        {},
        allowUnverifiedResponses: true,
        serverPublicKeysByHost: {
          'api.example.com': [key],
        },
        innerClient: MockClient((_) async => http.Response('unsigned', 200)),
      );
      addTearDown(client.close);
      expect((await client.get(Uri.parse('https://cdn.other.com/'))).body,
          'unsigned');
      await expectLater(client.get(Uri.parse('https://api.example.com/')),
          throwsA(isA<MissingSecurityHeaderException>()));
    });

    test('allowUnpinnedHosts lets hosts without keys pass unverified',
        () async {
      final client = HttpSecurityPinningClient.perHost(
        {},
        allowUnpinnedHosts: true,
        serverPublicKeysByHost: {
          'a.example.com': [key],
        },
        innerClient: MockClient((_) async => http.Response('third-party', 200)),
      );
      addTearDown(client.close);
      expect((await client.get(Uri.parse('https://cdn.other.com/'))).body,
          'third-party');
      await expectLater(client.get(Uri.parse('https://a.example.com/')),
          throwsA(isA<MissingSecurityHeaderException>()));
    });
  });

  test('UniversalSecurityClient on web verifies with serverPublicKeys',
      () async {
    final client = UniversalSecurityClient.create(
      spkiPins: [_pin],
      serverPublicKeys: [key],
      innerClient: signingServer('universal'),
    );
    addTearDown(client.close);
    expect((await client.get(Uri.parse('https://api.example.com/'))).body,
        'universal');
  });
}
