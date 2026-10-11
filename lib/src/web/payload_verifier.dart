// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'exceptions.dart';
import 'signature_base.dart';

/// Verifies `hsp-sig-v2` Ed25519 response signatures (see [SignatureBase]).
///
/// Used by the Flutter Web client, where browsers do not allow TLS pinning.
/// It checks that a response was produced, for exactly the request that was
/// sent, by a server holding one of the pinned Ed25519 private keys.
///
/// It does **not** provide confidentiality: requests and responses remain
/// readable by anyone able to intercept TLS.
class PayloadVerifier {
  /// Response header carrying the base64 Ed25519 signature.
  static const signatureHeader = 'x-hsp-signature';

  /// Response header carrying the signing time (milliseconds since epoch).
  static const createdHeader = 'x-hsp-created';

  /// Request header carrying the client nonce.
  static const nonceHeader = 'x-hsp-nonce';

  final List<SimplePublicKey> _publicKeys;

  /// The accepted difference between the signing time and the client clock,
  /// or `null` to skip the check (the nonce still binds each response to one
  /// request).
  final Duration? timestampTolerance;

  final Ed25519 _algorithm;

  /// Creates a verifier trusting the 32-byte Ed25519 [publicKeys].
  ///
  /// Configure the current key and the next one to rotate keys without
  /// breaking deployed clients. Throws an [ArgumentError] if [publicKeys] is
  /// empty or a key is not exactly 32 bytes.
  PayloadVerifier({
    required List<List<int>> publicKeys,
    this.timestampTolerance = const Duration(minutes: 5),
    Ed25519? algorithm,
  })  : _publicKeys = List.unmodifiable(publicKeys.map(_toPublicKey)),
        _algorithm = algorithm ?? Ed25519() {
    if (_publicKeys.isEmpty) {
      throw ArgumentError.value(
          publicKeys, 'publicKeys', 'must contain at least one key');
    }
    if (timestampTolerance != null && timestampTolerance! < Duration.zero) {
      throw ArgumentError.value(
          timestampTolerance, 'timestampTolerance', 'must not be negative');
    }
  }

  /// Creates a verifier from base64 (standard or URL-safe) encoded keys.
  factory PayloadVerifier.fromBase64(
    List<String> base64Keys, {
    Duration? timestampTolerance = const Duration(minutes: 5),
  }) {
    return PayloadVerifier(
      publicKeys: [for (final key in base64Keys) decodeBase64(key)],
      timestampTolerance: timestampTolerance,
    );
  }

  static SimplePublicKey _toPublicKey(List<int> bytes) {
    if (bytes.length != 32) {
      throw ArgumentError.value(bytes.length, 'publicKeys',
          'an Ed25519 public key must be exactly 32 bytes');
    }
    return SimplePublicKey(List.unmodifiable(bytes), type: KeyPairType.ed25519);
  }

  /// Decodes standard or URL-safe base64, with or without padding.
  static Uint8List decodeBase64(String value) {
    var cleaned = value.trim().replaceAll('-', '+').replaceAll('_', '/');
    final remainder = cleaned.length % 4;
    if (remainder != 0) {
      cleaned = cleaned.padRight(cleaned.length + 4 - remainder, '=');
    }
    return base64.decode(cleaned);
  }

  /// Verifies a response.
  ///
  /// [method] and [url] describe the request as it was sent (a response
  /// obtained through a redirect cannot be verified, since the redirect is not
  /// signed, and must be refused), [nonce] is the value sent in
  /// [nonceHeader], and
  /// [statusCode], [headers] and [bodyBytes] describe the response.
  ///
  /// Throws a [MissingSecurityHeaderException], a
  /// [MalformedSecurityHeaderException], a [ReplayAttackException] or a
  /// [SignatureVerificationException]; any other failure of the
  /// cryptographic library is reported as a [SignatureVerificationException].
  Future<void> verify({
    required String method,
    required Uri url,
    required int statusCode,
    required String nonce,
    required Map<String, String> headers,
    required List<int> bodyBytes,
    int? clientNowMs,
  }) async {
    final sigValue = _header(headers, signatureHeader);
    if (sigValue == null || sigValue.trim().isEmpty) {
      throw MissingSecurityHeaderException(signatureHeader);
    }
    final createdValue = _header(headers, createdHeader);
    if (createdValue == null || createdValue.trim().isEmpty) {
      throw MissingSecurityHeaderException(createdHeader);
    }
    final createdText = createdValue.trim();
    final createdMs = RegExp(r'^[0-9]{1,16}$').hasMatch(createdText)
        ? int.parse(createdText)
        : null;
    if (createdMs == null) {
      throw const MalformedSecurityHeaderException(
          'Invalid X-HSP-Created value; expected milliseconds since epoch.');
    }
    if (nonce.trim().isEmpty) {
      throw const MalformedSecurityHeaderException(
          'The request nonce is empty.');
    }

    final tolerance = timestampTolerance;
    if (tolerance != null) {
      final nowMs = clientNowMs ?? DateTime.now().millisecondsSinceEpoch;
      if ((nowMs - createdMs).abs() > tolerance.inMilliseconds) {
        throw ReplayAttackException(
          serverTimestampMs: createdMs,
          clientTimestampMs: nowMs,
          tolerance: tolerance,
        );
      }
    }

    final Uint8List signatureBytes;
    try {
      signatureBytes = decodeBase64(sigValue);
    } on FormatException catch (e) {
      throw SignatureVerificationException(
          'Signature is not valid base64: ${e.message}');
    }
    if (signatureBytes.length != 64) {
      throw SignatureVerificationException(
          'An Ed25519 signature must be 64 bytes, got ${signatureBytes.length}.');
    }

    final message = SignatureBase.build(
      method: method,
      url: url,
      statusCode: statusCode,
      nonce: nonce,
      createdMs: createdMs,
      contentType: _header(headers, 'content-type') ?? '',
      bodyBytes: bodyBytes,
    );

    for (final key in _publicKeys) {
      bool valid;
      try {
        valid = await _algorithm.verify(
          message,
          signature: Signature(signatureBytes, publicKey: key),
        );
      } catch (e) {
        throw SignatureVerificationException(
            'Signature could not be verified: $e');
      }
      if (valid) return;
    }
    throw const SignatureVerificationException();
  }

  static String? _header(Map<String, String> headers, String key) {
    final lowerKey = key.toLowerCase();
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == lowerKey) return entry.value;
    }
    return null;
  }
}
