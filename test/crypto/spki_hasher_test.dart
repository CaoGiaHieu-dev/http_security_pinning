import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
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

void main() {
  group('SpkiHasher with OpenSSL fixtures', () {
    late Map<String, dynamic> groundTruthPins;

    setUpAll(() {
      final jsonFile = File('test/fixtures/pins.json');
      groundTruthPins =
          json.decode(jsonFile.readAsStringSync()) as Map<String, dynamic>;
    });

    test('matches OpenSSL ground-truth pin for Root CA', () {
      final der =
          _pemToDer(File('test/fixtures/root_ca.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['root_ca']));
    });

    test('matches OpenSSL ground-truth pin for Intermediate CA', () {
      final der = _pemToDer(
          File('test/fixtures/intermediate_ca.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['intermediate_ca']));
    });

    test('matches OpenSSL ground-truth pin for Leaf A1', () {
      final der =
          _pemToDer(File('test/fixtures/server_a1.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['server_a1']));
    });

    test('matches OpenSSL ground-truth pin for Leaf A2 (same key, new cert)',
        () {
      final der =
          _pemToDer(File('test/fixtures/server_a2.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['server_a2']));
      // Renewal keeps the same SPKI pin!
      expect(pin, equals(groundTruthPins['server_a1']));
    });

    test('matches OpenSSL ground-truth pin for Leaf B (different key)', () {
      final der =
          _pemToDer(File('test/fixtures/server_b.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['server_b']));
      expect(pin, isNot(equals(groundTruthPins['server_a1'])));
    });

    test('matches OpenSSL ground-truth pin for EC curve leaf', () {
      final der =
          _pemToDer(File('test/fixtures/selfsigned.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['selfsigned']));
    });

    test(
        'matches OpenSSL ground-truth pin for X.509 v1 certificate (no version field)',
        () {
      final der = _pemToDer(File('test/fixtures/v1.pem').readAsStringSync());
      final pin = SpkiHasher.pinOf(der);
      expect(pin, equals(groundTruthPins['v1']));
    });

    test('throws CertificateFormatException on invalid input', () {
      expect(
        () => SpkiHasher.extractSpki(Uint8List(0)),
        throwsA(isA<CertificateFormatException>().having(
            (e) => e.message, 'message', contains('the input is empty'))),
      );
      expect(
        () => SpkiHasher.extractSpki(Uint8List.fromList([1, 2, 3, 4])),
        throwsA(isA<CertificateFormatException>()),
      );
      expect(
        () => SpkiHasher.extractSpki(
            Uint8List.fromList([0x30, 0x00])), // empty sequence
        throwsA(isA<CertificateFormatException>().having(
            (e) => e.message, 'message', contains('Certificate SEQUENCE'))),
      );
      expect(
        () => SpkiHasher.extractSpki(
            Uint8List.fromList([0x02, 0x01, 0x01])), // ASN1 Integer root
        throwsA(isA<CertificateFormatException>().having(
            (e) => e.message, 'message', contains('Certificate SEQUENCE'))),
      );
      expect(
        () => SpkiHasher.extractSpki(Uint8List.fromList([
          0x30,
          0x03,
          0x02,
          0x01,
          0x01
        ])), // cert has integer not TBS sequence
        throwsA(isA<CertificateFormatException>().having(
            (e) => e.message, 'message', contains('TBSCertificate SEQUENCE'))),
      );

      final certWithShortTbs = ASN1Sequence();
      final shortTbs = ASN1Sequence();
      shortTbs.add(ASN1Integer(BigInt.from(1)));
      shortTbs.add(ASN1Integer(BigInt.from(2)));
      certWithShortTbs.add(shortTbs);

      expect(
        () => SpkiHasher.extractSpki(certWithShortTbs.encodedBytes),
        throwsA(isA<CertificateFormatException>().having(
            (e) => e.message, 'message', contains('TBSCertificate has only'))),
      );

      final certWithInvalidSpki = ASN1Sequence();
      final invalidSpkiTbs = ASN1Sequence();
      for (var i = 0; i < 6; i++) {
        invalidSpkiTbs.add(ASN1Integer(BigInt.from(i)));
      }
      certWithInvalidSpki.add(invalidSpkiTbs);

      expect(
        () => SpkiHasher.extractSpki(certWithInvalidSpki.encodedBytes),
        throwsA(isA<CertificateFormatException>().having((e) => e.message,
            'message', contains('is not a SubjectPublicKeyInfo'))),
      );
    });
  });
}
