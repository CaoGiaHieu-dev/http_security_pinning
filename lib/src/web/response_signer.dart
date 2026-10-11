// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'payload_verifier.dart';
import 'signature_base.dart';

/// Server-side reference implementation of the `hsp-sig-v2` response
/// signature (see [SignatureBase]), for Dart servers and tests.
///
/// Servers in other languages must produce byte-identical signature bases;
/// the README contains a Node.js example and a test vector.
class ResponseSigner {
  final SimpleKeyPair _keyPair;
  final Ed25519 _algorithm;

  ResponseSigner._(this._keyPair, this._algorithm);

  /// Creates a signer from a 32-byte Ed25519 private key seed.
  static Future<ResponseSigner> fromSeed(List<int> seed) async {
    if (seed.length != 32) {
      throw ArgumentError.value(
          seed.length, 'seed', 'an Ed25519 seed must be exactly 32 bytes');
    }
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPairFromSeed(seed);
    return ResponseSigner._(keyPair, algorithm);
  }

  /// The 32-byte public key to pin in clients.
  Future<List<int>> publicKeyBytes() async =>
      (await _keyPair.extractPublicKey()).bytes;

  /// Signs a response and returns the headers to add to it
  /// (`X-HSP-Signature` and `X-HSP-Created`).
  ///
  /// [method], [url] and [nonce] come from the request (use the public URL
  /// the client called, not an internal one rewritten by a proxy); the other
  /// arguments describe the response exactly as the client will receive it.
  Future<Map<String, String>> sign({
    required String method,
    required Uri url,
    required int statusCode,
    required String nonce,
    required String contentType,
    required List<int> bodyBytes,
    int? createdMs,
  }) async {
    final created = createdMs ?? DateTime.now().millisecondsSinceEpoch;
    final message = SignatureBase.build(
      method: method,
      url: url,
      statusCode: statusCode,
      nonce: nonce,
      createdMs: created,
      contentType: contentType,
      bodyBytes: bodyBytes,
    );
    final signature = await _algorithm.sign(message, keyPair: _keyPair);
    return {
      PayloadVerifier.signatureHeader: base64.encode(signature.bytes),
      PayloadVerifier.createdHeader: '$created',
    };
  }
}
