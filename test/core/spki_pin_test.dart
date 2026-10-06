import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('SpkiPin', () {
    const validBase64 = '6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY=';
    final validBytes = base64.decode(validBase64);

    test('parses standard base64 pin', () {
      final pin = SpkiPin.parse(validBase64);
      expect(pin.base64Value, validBase64);
      expect(pin.bytes, validBytes);
      expect(pin.toString(), validBase64);
    });

    test('parses with sha256/ prefix (HPKP / OkHttp style)', () {
      final pin = SpkiPin.parse('sha256/$validBase64');
      expect(pin.base64Value, validBase64);
    });

    test('parses with sha256= prefix and trims whitespace', () {
      final pin = SpkiPin.parse('  sha256=$validBase64 \n ');
      expect(pin.base64Value, validBase64);
    });

    test('parses URL-safe base64 and unpadded base64', () {
      final urlSafe = validBase64.replaceAll('+', '-').replaceAll('/', '_');
      final pin = SpkiPin.parse(urlSafe);
      expect(pin.base64Value, validBase64);

      final unpadded = validBase64.replaceAll('=', '');
      final pin2 = SpkiPin.parse(unpadded);
      expect(pin2.base64Value, validBase64);
    });

    test('fromBytes creates pin from 32-byte digest', () {
      final pin = SpkiPin.fromBytes(Uint8List.fromList(validBytes));
      expect(pin.base64Value, validBase64);
    });

    test('rejects empty pin', () {
      expect(() => SpkiPin.parse(''), throwsA(isA<InvalidPinException>()));
      expect(() => SpkiPin.parse('   '), throwsA(isA<InvalidPinException>()));
      expect(
          () => SpkiPin.parse('sha256/'), throwsA(isA<InvalidPinException>()));
    });

    test('rejects malformed base64', () {
      expect(
        () => SpkiPin.parse('not_valid_base64!!!'),
        throwsA(isA<InvalidPinException>()),
      );
    });

    test('rejects invalid length (not 32 bytes)', () {
      // 16 bytes base64 (e.g. MD5)
      const shortPin = 'dGVzdA==';
      expect(
          () => SpkiPin.parse(shortPin), throwsA(isA<InvalidPinException>()));

      expect(
        () => SpkiPin.fromBytes(Uint8List(31)),
        throwsA(isA<InvalidPinException>()),
      );
      expect(
        () => SpkiPin.fromBytes(Uint8List(33)),
        throwsA(isA<InvalidPinException>()),
      );
    });

    test('matches performs constant-time comparison', () {
      final pin = SpkiPin.parse(validBase64);
      expect(pin.matches(validBytes), isTrue);

      final mutated = List<int>.from(validBytes);
      mutated[0] ^= 1;
      expect(pin.matches(mutated), isFalse);

      expect(pin.matches(Uint8List(10)), isFalse);
    });

    test('equality and hashCode', () {
      final pin1 = SpkiPin.parse(validBase64);
      final pin2 = SpkiPin.parse('sha256/$validBase64');
      final pin3 = SpkiPin.fromBytes(Uint8List(32));

      expect(pin1, equals(pin2));
      expect(pin1.hashCode, equals(pin2.hashCode));
      expect(pin1, isNot(equals(pin3)));
    });
  });
}
