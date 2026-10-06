import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('CertificatePinningException hierarchy', () {
    test('CertificateFetchException isRetryable logic', () {
      final retryable = CertificateFetchException('Timeout', code: 'TIMEOUT');
      expect(retryable.isRetryable, isTrue);

      final nonRetryableUrl =
          CertificateFetchException('Invalid', code: 'INVALID_URL');
      expect(nonRetryableUrl.isRetryable, isFalse);

      final nonRetryableArgs =
          CertificateFetchException('Args', code: 'INVALID_ARGS');
      expect(nonRetryableArgs.isRetryable, isFalse);

      final nonRetryablePlugin =
          CertificateFetchException('Missing', code: 'MISSING_PLUGIN');
      expect(nonRetryablePlugin.isRetryable, isFalse);

      expect(
          retryable.toString(), contains('Failed to fetch certificate chain'));
    });

    test('InsecureConnectionException formatting', () {
      final exc =
          InsecureConnectionException(Uri.parse('http://example.com/api'));
      expect(exc.url.scheme, 'http');
      expect(exc.toString(),
          contains('Refusing to open a non-HTTPS connection to example.com'));
    });

    test('UnpinnedHostException formatting', () {
      final exc = UnpinnedHostException('unpinned.com');
      expect(exc.host, 'unpinned.com');
      expect(exc.toString(),
          contains('No SPKI pins are configured for host: unpinned.com'));
    });

    test('InvalidPinException formatting', () {
      final exc = InvalidPinException('bad_pin', 'too short');
      expect(exc.pin, 'bad_pin');
      expect(exc.toString(), contains('Invalid SPKI pin "bad_pin": too short'));
    });

    test('NoValidPinsFoundException formatting with and without observed pins',
        () {
      final withObserved = NoValidPinsFoundException('example.com',
          observedPins: ['pin1', 'pin2']);
      expect(withObserved.toString(), contains('server presented: pin1, pin2'));

      final empty = NoValidPinsFoundException('example.com');
      expect(empty.toString(),
          contains('No valid SPKI pins found for host: example.com'));
    });
  });
}
