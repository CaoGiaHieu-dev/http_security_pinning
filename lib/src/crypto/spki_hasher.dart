import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';

import '../core/exceptions.dart';

/// Extracts and hashes the Subject Public Key Info (SPKI) of DER certificates.
abstract final class SpkiHasher {
  /// ASN.1 tag of the explicit `[0]` wrapper around the certificate version.
  static const int _versionTag = 0xA0;

  /// Number of TBSCertificate fields that precede the SPKI when the (optional)
  /// version is absent: serialNumber, signature, issuer, validity, subject.
  static const int _fieldsBeforeSpki = 5;

  /// Returns the DER encoded SubjectPublicKeyInfo of [certificateDer].
  ///
  /// Unlike a fixed index lookup this works for X.509 v1 certificates, which
  /// omit the version field, as well as v2/v3 certificates.
  ///
  /// Throws a [CertificateFormatException] if the data is not a certificate.
  static Uint8List extractSpki(Uint8List certificateDer) {
    try {
      final parser = ASN1Parser(certificateDer);
      if (!parser.hasNext()) {
        throw CertificateFormatException('the input is empty.');
      }
      final certificate = parser.nextObject();
      if (certificate is! ASN1Sequence || certificate.elements.isEmpty) {
        throw CertificateFormatException('expected a Certificate SEQUENCE.');
      }
      final tbs = certificate.elements.first;
      if (tbs is! ASN1Sequence) {
        throw CertificateFormatException('expected a TBSCertificate SEQUENCE.');
      }

      final fields = tbs.elements;
      final hasVersion = fields.isNotEmpty && fields.first.tag == _versionTag;
      final spkiIndex = _fieldsBeforeSpki + (hasVersion ? 1 : 0);
      if (fields.length <= spkiIndex) {
        throw CertificateFormatException(
          'TBSCertificate has only ${fields.length} fields.',
        );
      }

      final spki = fields[spkiIndex];
      if (spki is! ASN1Sequence ||
          spki.elements.length != 2 ||
          spki.elements[0] is! ASN1Sequence ||
          spki.elements[1] is! ASN1BitString) {
        throw CertificateFormatException(
          'field $spkiIndex is not a SubjectPublicKeyInfo.',
        );
      }
      return spki.encodedBytes;
    } on CertificateFormatException {
      rethrow;
    } catch (e) {
      // asn1lib reports truncated/garbled input with assorted core errors.
      throw CertificateFormatException('$e');
    }
  }

  /// Returns the SHA-256 digest of the SPKI of [certificateDer].
  static Uint8List sha256Digest(Uint8List certificateDer) =>
      Uint8List.fromList(sha256.convert(extractSpki(certificateDer)).bytes);

  /// Returns the pin of [certificateDer] in the textual (base64) form that
  /// can be passed to `HttpSecurityPinningClient`.
  static String pinOf(Uint8List certificateDer) =>
      base64.encode(sha256Digest(certificateDer));
}
