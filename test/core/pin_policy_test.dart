import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('PinPolicy', () {
    final pinA = SpkiPin.parse('6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=');
    final pinB = SpkiPin.parse('BL/ENt1pniuxdP4R9oTSx3S+59B0WwjuvTbegSTdY18=');

    group('uniform policy', () {
      test('applies same pins to any host', () {
        final policy = PinPolicy.uniform([pinA]);
        expect(policy.pinsFor('example.com'), equals({pinA}));
        expect(policy.pinsFor('api.other.com'), equals({pinA}));
      });

      test('empty pins returns null (unpinned)', () {
        final policy = PinPolicy.uniform([]);
        expect(policy.pinsFor('example.com'), isNull);
      });
    });

    group('perHost policy', () {
      test('exact match is case-insensitive', () {
        final policy = PinPolicy.perHost({
          'api.example.com': [pinA],
        });
        expect(policy.pinsFor('api.example.com'), equals({pinA}));
        expect(policy.pinsFor('API.EXAMPLE.COM'), equals({pinA}));
      });

      test('wildcard matches subdomains', () {
        final policy = PinPolicy.perHost({
          '*.example.com': [pinA],
        });
        expect(policy.pinsFor('api.example.com'), equals({pinA}));
        expect(policy.pinsFor('auth.dev.example.com'), equals({pinA}));
        // Root domain is not a subdomain of *.example.com
        expect(
          () => policy.pinsFor('example.com'),
          throwsA(isA<UnpinnedHostException>()),
        );
      });

      test('exact match takes precedence over wildcard', () {
        final policy = PinPolicy.perHost({
          '*.example.com': [pinA],
          'special.example.com': [pinB],
        });
        expect(policy.pinsFor('special.example.com'), equals({pinB}));
        expect(policy.pinsFor('other.example.com'), equals({pinA}));
      });

      test('longer wildcard takes precedence over shorter wildcard', () {
        final policy = PinPolicy.perHost({
          '*.example.com': [pinA],
          '*.corp.example.com': [pinB],
        });
        expect(policy.pinsFor('app.corp.example.com'), equals({pinB}));
        expect(policy.pinsFor('app.other.example.com'), equals({pinA}));
      });

      test('unpinned hosts throw UnpinnedHostException when disallowed', () {
        final policy = PinPolicy.perHost({
          'api.example.com': [pinA],
        }, allowUnpinnedHosts: false);

        expect(
          () => policy.pinsFor('unknown.com'),
          throwsA(isA<UnpinnedHostException>()),
        );
      });

      test('unpinned hosts return null when allowed', () {
        final policy = PinPolicy.perHost({
          'api.example.com': [pinA],
        }, allowUnpinnedHosts: true);

        expect(policy.pinsFor('unknown.com'), isNull);
      });

      test('rejects invalid host patterns and empty pins', () {
        expect(
          () => PinPolicy.perHost({
            '': [pinA]
          }),
          throwsArgumentError,
        );
        expect(
          () => PinPolicy.perHost({
            '*': [pinA]
          }),
          throwsArgumentError,
        );
        expect(
          () => PinPolicy.perHost({
            'api.*.example.com': [pinA]
          }),
          throwsArgumentError,
        );
        expect(
          () => PinPolicy.perHost({'api.example.com': []}),
          throwsArgumentError,
        );
      });
    });
  });
}
