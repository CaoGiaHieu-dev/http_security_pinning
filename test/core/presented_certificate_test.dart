import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

Uint8List _pemToDer(String pem) {
  final clean = pem
      .replaceAll('\r', '')
      .split('\n')
      .map((l) => l.trim())
      .where((line) =>
          line.isNotEmpty &&
          !line.startsWith('-----BEGIN') &&
          !line.startsWith('-----END'))
      .join();
  return Uint8List.fromList(base64.decode(clean));
}

void main() {
  const f = 'test/fixtures/';

  group('PresentedCertificate', () {
    test('parses valid X.509 v3 certificate correctly', () {
      final pem = File('${f}server_a1.pem').readAsStringSync();
      final der = _pemToDer(pem);

      final cert = PresentedCertificate.fromDer(der);

      expect(cert.der, equals(der));
      expect(cert.sha1, isNotEmpty);
      expect(cert.sha1.length, 20);
      expect(cert.pem, contains('-----BEGIN CERTIFICATE-----'));
      expect(cert.pem, contains('-----END CERTIFICATE-----'));
      expect(cert.subject, contains('localhost'));
      expect(cert.issuer, contains('Pinning Test Intermediate CA'));
      expect(cert.startValidity.isBefore(cert.endValidity), isTrue);
    });

    test('parses X.509 v1 certificate without version field', () {
      final pem = File('${f}v1.pem').readAsStringSync();
      final der = _pemToDer(pem);

      final cert = PresentedCertificate.fromDer(der);

      expect(cert.der, equals(der));
      expect(cert.subject, contains('v1'));
      expect(cert.issuer, contains('v1'));
      expect(cert.startValidity.year, greaterThanOrEqualTo(2020));
    });

    test('parses EC self-signed certificate', () {
      final pem = File('${f}selfsigned.pem').readAsStringSync();
      final der = _pemToDer(pem);

      final cert = PresentedCertificate.fromDer(der);

      expect(cert.der, equals(der));
      expect(cert.subject, contains('localhost'));
      expect(cert.issuer, contains('localhost'));
    });

    test('falls back gracefully to default values when given garbage bytes',
        () {
      final garbage = Uint8List.fromList([0, 1, 2, 3, 4, 5]);
      final cert = PresentedCertificate.fromDer(garbage);

      expect(cert.der, equals(garbage));
      expect(cert.sha1.length, 20);
      expect(cert.subject, 'UNKNOWN');
      expect(cert.issuer, 'UNKNOWN');
      expect(cert.startValidity,
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
      expect(cert.endValidity,
          DateTime.fromMillisecondsSinceEpoch(0, isUtc: true));
    });

    test('derToPem formats lines correctly with 64 characters per line', () {
      final data = Uint8List.fromList(List.generate(100, (i) => i));
      final pem = PresentedCertificate.derToPem(data);

      expect(pem.startsWith('-----BEGIN CERTIFICATE-----\n'), isTrue);
      expect(pem.endsWith('-----END CERTIFICATE-----\n'), isTrue);
      final lines = pem
          .split('\n')
          .where((l) => !l.startsWith('-----') && l.isNotEmpty)
          .toList();
      expect(lines.first.length, 64);
    });
  });
}
