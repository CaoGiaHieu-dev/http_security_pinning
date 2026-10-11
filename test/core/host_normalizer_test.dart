// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('HostNormalizer', () {
    test('lower-cases, trims and drops one trailing dot', () {
      expect(HostNormalizer.normalize(' API.Example.COM. '), 'api.example.com');
      expect(HostNormalizer.normalize('localhost.'), 'localhost');
      expect(HostNormalizer.normalize('127.0.0.1'), '127.0.0.1');
      expect(HostNormalizer.normalize('::1'), '::1');
    });

    test('converts internationalized labels to punycode (RFC 3492)', () {
      expect(HostNormalizer.normalize('bücher.de'), 'xn--bcher-kva.de');
      expect(HostNormalizer.normalize('MÜNCHEN.de'), 'xn--mnchen-3ya.de');
      expect(HostNormalizer.normalize('中国'), 'xn--fiqs8s');
      expect(HostNormalizer.normalize('xn--bcher-kva.de'), 'xn--bcher-kva.de');
    });

    test('IO-1 canonicalizes IP literals', () {
      for (final (input, expected) in [
        ('127.1', '127.0.0.1'),
        ('2130706433', '127.0.0.1'),
        ('0x7f.0.0.1', '127.0.0.1'),
        ('0177.0.0.01', '127.0.0.1'),
        ('10.1.256', '10.1.1.0'),
        ('0:0:0:0:0:0:0:1', '::1'),
        ('[0:0:0:0:0:0:0:1]', '::1'),
        ('::ffff:127.0.0.1', '127.0.0.1'),
        ('2001:DB8:0:0:1:0:0:1', '2001:db8::1:0:0:1'),
        ('fe80:0:0:0:0:0:0:0', 'fe80::'),
      ]) {
        expect(HostNormalizer.normalize(input), expected, reason: input);
      }
      final pin = SpkiPin.parse('6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=');
      final policy = PinPolicy.perHost(
        {
          '[::1]': [pin],
          '127.0.0.1': [pin]
        },
        allowUnpinnedHosts: true,
      );
      expect(
          policy.pinsFor(Uri.parse('https://[0:0:0:0:0:0:0:1]/').host), {pin});
      expect(policy.pinsFor('127.1'), {pin});
      expect(policy.pinsFor('2130706433'), {pin});
      expect(policy.pinsFor('::ffff:7f00:1'), {pin});
    });

    test('IO-2 isValid rejects control characters and URL syntax', () {
      final crlf = HostNormalizer.normalize(
          Uri.parse('https://evil%0D%0Ax.example.com/').host);
      expect(HostNormalizer.isValid(crlf), isFalse);
      for (final bad in ['a b.com', 'a/b', 'a@b', '', 'a%b']) {
        expect(HostNormalizer.isValid(bad), isFalse, reason: bad);
      }
      for (final good in [
        'xn--bcher-kva.de',
        'a_b.example.com',
        '::1',
        '1.2.3.4'
      ]) {
        expect(HostNormalizer.isValid(good), isTrue, reason: good);
      }
    });

    test('decodes the percent-encoding produced by Uri', () {
      final host = Uri.parse('https://BÜcher.de./x').host;
      expect(HostNormalizer.normalize(host), 'xn--bcher-kva.de');
    });

    test('per-host policies match every spelling of the same host', () {
      final pin = SpkiPin.parse('6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=');
      final policy = PinPolicy.perHost({
        'bücher.de': [pin],
        '*.Example.com.': [pin],
      });
      for (final host in [
        'xn--bcher-kva.de',
        'BÜCHER.de.',
        Uri.parse('https://bücher.de/').host,
        'api.example.com.',
        'A.B.EXAMPLE.COM',
      ]) {
        expect(policy.pinsFor(host), {pin}, reason: host);
      }
      expect(() => policy.pinsFor('example.com'),
          throwsA(isA<UnpinnedHostException>()));
    });

    test('rejects host patterns with ports, paths or inner wildcards', () {
      final pin = SpkiPin.parse('6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=');
      for (final pattern in [
        'example.com:443',
        'example.com/x',
        'a.*.com',
        '*',
        '*.',
        '.example.com',
        'exa mple.com',
        '*.::1',
        '*.10.0.0.1',
      ]) {
        expect(
            () => PinPolicy.perHost({
                  pattern: [pin]
                }),
            throwsArgumentError,
            reason: pattern);
      }
      expect(
          PinPolicy.perHost({
            '[::1]': [pin]
          }).pinsFor('::1'),
          {pin});
    });
  });
}
