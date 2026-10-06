import 'dart:convert';
import 'dart:typed_data';

import 'exceptions.dart';

/// A validated Subject Public Key Info (SPKI) SHA-256 pin.
///
/// Holds the 32-byte raw digest and offers a constant-time comparison helper
/// to prevent timing attacks.
final class SpkiPin {
  /// The 32-byte SHA-256 digest of the SubjectPublicKeyInfo.
  final Uint8List digest;

  /// The raw 32 bytes of the digest (alias for [digest]).
  Uint8List get bytes => digest;

  /// The standard, padded base64 representation of [digest].
  final String base64Value;

  /// Creates a pin directly from its 32-byte [digest].
  SpkiPin.fromBytes(List<int> bytes)
      : digest = Uint8List.fromList(bytes),
        base64Value = base64.encode(bytes) {
    if (digest.length != 32) {
      throw InvalidPinException(
        base64Value,
        'SHA-256 pin must be exactly 32 bytes, got ${digest.length}.',
      );
    }
  }

  /// Parses a pin string into an [SpkiPin].
  ///
  /// Accepts:
  /// * standard base64 (e.g. `e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=`)
  /// * HPKP / OkHttp style `sha256/` or `sha256=` prefix
  /// * unpadded base64 and URL-safe base64
  factory SpkiPin.parse(String rawPin) {
    var cleaned = rawPin.trim();
    if (cleaned.startsWith('sha256/') || cleaned.startsWith('sha256=')) {
      cleaned = cleaned.substring(7).trim();
    }
    if (cleaned.isEmpty) {
      throw InvalidPinException(rawPin, 'pin is empty.');
    }

    // Normalize URL-safe base64 to standard base64
    cleaned = cleaned.replaceAll('-', '+').replaceAll('_', '/');

    // Add padding if missing
    final remainder = cleaned.length % 4;
    if (remainder != 0) {
      cleaned = cleaned.padRight(cleaned.length + (4 - remainder), '=');
    }

    Uint8List bytes;
    try {
      bytes = Uint8List.fromList(base64.decode(cleaned));
    } on FormatException catch (e) {
      throw InvalidPinException(rawPin, 'not valid base64 (${e.message}).');
    }

    if (bytes.length != 32) {
      throw InvalidPinException(
        rawPin,
        'SHA-256 pin must decode to 32 bytes, got ${bytes.length}.',
      );
    }

    return SpkiPin._(bytes, base64.encode(bytes));
  }

  const SpkiPin._(this.digest, this.base64Value);

  /// Performs a constant-time comparison against an observed SPKI [otherDigest].
  ///
  /// Constant-time matching avoids leaking timing information about whether and
  /// how many bytes matched.
  bool matches(List<int> otherDigest) {
    if (digest.length != otherDigest.length) return false;
    var result = 0;
    for (var i = 0; i < digest.length; i++) {
      result |= digest[i] ^ otherDigest[i];
    }
    return result == 0;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is SpkiPin && base64Value == other.base64Value);

  @override
  int get hashCode => base64Value.hashCode;

  @override
  String toString() => base64Value;
}
