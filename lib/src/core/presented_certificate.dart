import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';

/// An [X509Certificate] constructed from raw DER bytes.
///
/// Used to represent certificates collected during the handshake probe, so they
/// can be inspected by [HttpClient.badCertificateCallback] if certificate
/// pinning fails, enabling detailed certificate inspection and diagnostics.
class PresentedCertificate implements X509Certificate {
  @override
  final Uint8List der;

  @override
  final Uint8List sha1;

  @override
  final String pem;

  @override
  final String subject;

  @override
  final String issuer;

  @override
  final DateTime startValidity;

  @override
  final DateTime endValidity;

  /// Creates a [PresentedCertificate] from raw [der] bytes.
  factory PresentedCertificate.fromDer(Uint8List der) {
    final sha1Digest = Uint8List.fromList(cryptoSha1.convert(der).bytes);
    final pemString = derToPem(der);

    String subjectStr = 'UNKNOWN';
    String issuerStr = 'UNKNOWN';
    DateTime notBefore = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);
    DateTime notAfter = DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

    try {
      final parser = ASN1Parser(der);
      if (parser.hasNext()) {
        final root = parser.nextObject();
        if (root is ASN1Sequence && root.elements.isNotEmpty) {
          final tbs = root.elements.first;
          if (tbs is ASN1Sequence) {
            final elements = tbs.elements;
            int offset = 0;
            // Check for optional explicit version tag [0]
            if (elements.isNotEmpty && elements[0].tag == 0xA0) {
              offset = 1;
            }

            // Expected TBS order after version:
            // 0: serialNumber
            // 1: signatureAlgorithm
            // 2: issuer
            // 3: validity
            // 4: subject
            // 5: SPKI
            if (elements.length > offset + 2) {
              issuerStr = _formatX509Name(elements[offset + 2]);
            }
            if (elements.length > offset + 3) {
              final validitySeq = elements[offset + 3];
              if (validitySeq is ASN1Sequence &&
                  validitySeq.elements.length >= 2) {
                notBefore =
                    _parseAsn1Time(validitySeq.elements[0]) ?? notBefore;
                notAfter = _parseAsn1Time(validitySeq.elements[1]) ?? notAfter;
              }
            }
            if (elements.length > offset + 4) {
              subjectStr = _formatX509Name(elements[offset + 4]);
            }
          }
        }
      }
    } catch (_) {
      // Best-effort parsing: failure to extract non-essential metadata
      // should never prevent certificate validation.
    }

    return PresentedCertificate._(
      der: Uint8List.fromList(der),
      sha1: sha1Digest,
      pem: pemString,
      subject: subjectStr,
      issuer: issuerStr,
      startValidity: notBefore,
      endValidity: notAfter,
    );
  }

  const PresentedCertificate._({
    required this.der,
    required this.sha1,
    required this.pem,
    required this.subject,
    required this.issuer,
    required this.startValidity,
    required this.endValidity,
  });

  /// Converts DER bytes into standard PEM format.
  static String derToPem(Uint8List derBytes) {
    final b64 = base64.encode(derBytes);
    final buffer = StringBuffer('-----BEGIN CERTIFICATE-----\n');
    for (var i = 0; i < b64.length; i += 64) {
      buffer.writeln(b64.substring(i, math.min(i + 64, b64.length)));
    }
    buffer.write('-----END CERTIFICATE-----\n');
    return buffer.toString();
  }

  static String _formatX509Name(ASN1Object nameObj) {
    try {
      if (nameObj is! ASN1Sequence) return nameObj.toString();
      final parts = <String>[];
      for (final set in nameObj.elements) {
        if (set is ASN1Set) {
          for (final attr in set.elements) {
            if (attr is ASN1Sequence && attr.elements.length >= 2) {
              final val = attr.elements[1];
              String valStr = '';
              if (val is ASN1PrintableString) {
                valStr = val.stringValue;
              } else if (val is ASN1UTF8String) {
                valStr = val.utf8StringValue;
              } else if (val is ASN1IA5String) {
                valStr = val.stringValue;
              } else {
                valStr = val.toString();
              }
              parts.add(valStr);
            }
          }
        }
      }
      return parts.isEmpty ? nameObj.toString() : parts.join(', ');
    } catch (_) {
      return nameObj.toString();
    }
  }

  static DateTime? _parseAsn1Time(ASN1Object timeObj) {
    try {
      if (timeObj is ASN1UtcTime) {
        return timeObj.dateTimeValue;
      } else if (timeObj is ASN1GeneralizedTime) {
        return timeObj.dateTimeValue;
      }
    } catch (_) {}
    return null;
  }
}

// Alias for crypto sha1
const cryptoSha1 = sha1;
