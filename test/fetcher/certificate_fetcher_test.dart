// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('MethodChannelCertificateFetcher', () {
    const channel = MethodChannel(MethodChannelCertificateFetcher.channelName);
    final targetUrl = Uri.parse('https://example.com:443');

    tearDown(() {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null);
    });

    test('successfully returns certificate chain from channel', () async {
      final fakeCert1 = Uint8List.fromList([1, 2, 3]);
      final fakeCert2 = Uint8List.fromList([4, 5, 6]);

      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        if (call.method == 'fetchHostCertificates') {
          // Only the origin is sent to the platform.
          expect(call.arguments['url'], 'https://example.com/');
          expect(call.arguments['host'], 'example.com');
          expect(call.arguments['port'], 443);
          expect(call.arguments['timeout'], 5000);
          return [fakeCert1, fakeCert2];
        }
        return null;
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      final chain = await fetcher.fetchChain(
        targetUrl,
        const Duration(seconds: 5),
      );

      expect(chain.length, 2);
      expect(chain[0], fakeCert1);
      expect(chain[1], fakeCert2);
    });

    test('sends only the origin and rounds sub-millisecond timeouts up',
        () async {
      Map<Object?, Object?>? args;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        args = call.arguments as Map<Object?, Object?>;
        return [
          Uint8List.fromList([1])
        ];
      });

      await MethodChannelCertificateFetcher(channel).fetchChain(
        Uri.parse('https://user:secret@example.com:8443/p/a?token=x#f'),
        const Duration(microseconds: 10),
      );
      expect(args!['url'], 'https://example.com:8443/');
      expect(args!['timeout'], 1);

      await MethodChannelCertificateFetcher(channel).fetchChain(
          Uri.parse('https://Bücher.DE./'), const Duration(seconds: 1));
      expect(args!['host'], 'xn--bcher-kva.de');
      expect(args!['url'], 'https://xn--bcher-kva.de/');
    });

    test('forwards the proxy to the platform', () async {
      Map<Object?, Object?>? args;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        args = call.arguments as Map<Object?, Object?>;
        return [
          Uint8List.fromList([1])
        ];
      });
      await MethodChannelCertificateFetcher(channel).fetchChainThroughProxy(
        targetUrl,
        const Duration(seconds: 1),
        ProxyDirective.parse('PROXY u:p@proxy.local:3128')!,
      );
      expect(args!['proxyHost'], 'proxy.local');
      expect(args!['proxyPort'], 3128);
      expect(args!['proxyAuthorization'], 'Basic dTpw');
    });

    test('rejects a non-positive timeout', () async {
      await expectLater(
        MethodChannelCertificateFetcher(channel)
            .fetchChain(targetUrl, Duration.zero),
        throwsArgumentError,
      );
    });

    test(
        'throws CertificateFetchException when channel returns empty or null list',
        () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        return <Uint8List>[];
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'NO_CERTIFICATES')),
      );
    });

    test('translates PlatformException to CertificateFetchException', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        throw PlatformException(
          code: 'CONNECTION_FAILED',
          message: 'Host unreachable',
        );
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'CONNECTION_FAILED')
            .having((e) => e.message, 'message', contains('Host unreachable'))),
      );
    });

    test('translates MissingPluginException to CertificateFetchException',
        () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        throw MissingPluginException();
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(seconds: 5)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'MISSING_PLUGIN')),
      );
    });

    test('handles timeout from channel', () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (MethodCall call) async {
        // A hanging completer future that never finishes
        await Completer<void>().future;
        return <Uint8List>[];
      });

      final fetcher = MethodChannelCertificateFetcher(channel);
      expect(
        () => fetcher.fetchChain(targetUrl, const Duration(milliseconds: 50)),
        throwsA(isA<CertificateFetchException>()
            .having((e) => e.code, 'code', 'TIMEOUT')),
      );
    });
  });

  group('HttpSecurityPinningPlugin desktop registrar', () {
    test('registerWith runs without error', () {
      expect(HttpSecurityPinningPlugin.registerWith, returnsNormally);
    });
  });
}
