// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

import 'exceptions.dart';

/// Cryptographic verifier that ensures response authenticity and integrity
/// on Flutter Web using Ed25519 public key pinning and replay attack protection.
class PayloadVerifier {
  /// Header key for the Ed25519 digital signature in Base64.
  static const defaultSignatureHeader = 'x-server-signature';

  /// Header key for the server generation timestamp in milliseconds since epoch.
  static const defaultTimestampHeader = 'x-signature-timestamp';

  /// Optional header key for the cryptographic nonce.
  static const defaultNonceHeader = 'x-signature-nonce';

  final SimplePublicKey _pinnedPublicKey;
  final Duration timestampTolerance;
  final String signatureHeader;
  final String timestampHeader;
  final String nonceHeader;
  final Ed25519 _algorithm;

  /// Creates a [PayloadVerifier] with the server's 32-byte Ed25519 [pinnedPublicKeyBytes].
  PayloadVerifier({
    required List<int> pinnedPublicKeyBytes,
    this.timestampTolerance = const Duration(minutes: 5),
    this.signatureHeader = defaultSignatureHeader,
    this.timestampHeader = defaultTimestampHeader,
    this.nonceHeader = defaultNonceHeader,
    Ed25519? algorithm,
  })  : _pinnedPublicKey = SimplePublicKey(
          pinnedPublicKeyBytes,
          type: KeyPairType.ed25519,
        ),
        _algorithm = algorithm ?? Ed25519();

  /// Creates a [PayloadVerifier] from a Base64-encoded Ed25519 public key string.
  factory PayloadVerifier.fromBase64(
    String base64Key, {
    Duration timestampTolerance = const Duration(minutes: 5),
    String signatureHeader = defaultSignatureHeader,
    String timestampHeader = defaultTimestampHeader,
    String nonceHeader = defaultNonceHeader,
  }) {
    return PayloadVerifier(
      pinnedPublicKeyBytes: base64.decode(base64Key.trim()),
      timestampTolerance: timestampTolerance,
      signatureHeader: signatureHeader,
      timestampHeader: timestampHeader,
      nonceHeader: nonceHeader,
    );
  }

  /// Verifies that [bodyBytes] matches the digital signature provided in [headers].
  ///
  /// Throws [MissingSecurityHeaderException] if required headers are absent.
  /// Throws [ReplayAttackException] if the timestamp exceeds [timestampTolerance].
  /// Throws [SignatureVerificationException] if the cryptographic signature is invalid.
  Future<void> verify({
    required List<int> bodyBytes,
    required Map<String, String> headers,
    int? clientNowMs,
  }) async {
    final sigValue = _getHeaderCaseInsensitive(headers, signatureHeader);
    if (sigValue == null || sigValue.trim().isEmpty) {
      throw MissingSecurityHeaderException(signatureHeader);
    }

    final tsValue = _getHeaderCaseInsensitive(headers, timestampHeader);
    if (tsValue == null || tsValue.trim().isEmpty) {
      throw MissingSecurityHeaderException(timestampHeader);
    }

    final serverTimestampMs = int.tryParse(tsValue.trim());
    if (serverTimestampMs == null) {
      throw const MalformedSecurityHeaderException(
        'Invalid timestamp format in header',
      );
    }

    // Verify replay protection window
    final currentMs = clientNowMs ?? DateTime.now().millisecondsSinceEpoch;
    final diff = (currentMs - serverTimestampMs).abs();
    if (diff > timestampTolerance.inMilliseconds) {
      throw ReplayAttackException(
        serverTimestampMs: serverTimestampMs,
        clientTimestampMs: currentMs,
        tolerance: timestampTolerance,
      );
    }

    // Construct data to verify: UTF-8(Timestamp) + UTF-8(Nonce) + BodyBytes
    final nonceValue = _getHeaderCaseInsensitive(headers, nonceHeader);
    final dataToVerify = <int>[
      ...utf8.encode(tsValue.trim()),
      if (nonceValue != null && nonceValue.isNotEmpty)
        ...utf8.encode(nonceValue.trim()),
      ...bodyBytes,
    ];

    final Uint8List signatureBytes;
    try {
      signatureBytes = base64.decode(sigValue.trim());
    } catch (e) {
      throw SignatureVerificationException(
        'Failed to decode Base64 signature: $e',
      );
    }

    final isValid = await _algorithm.verify(
      dataToVerify,
      signature: Signature(signatureBytes, publicKey: _pinnedPublicKey),
    );

    if (!isValid) {
      throw const SignatureVerificationException();
    }
  }

  static String? _getHeaderCaseInsensitive(
    Map<String, String> headers,
    String key,
  ) {
    final lowerKey = key.toLowerCase();
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == lowerKey) {
        return entry.value;
      }
    }
    return null;
  }
}
