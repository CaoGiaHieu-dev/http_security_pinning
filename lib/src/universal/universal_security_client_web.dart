// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:http/http.dart' as http;

import '../client/client_web.dart';

/// Unified cross-platform security client factory.
///
/// The parameters are identical on every platform, but each platform only
/// uses the ones it can enforce:
///
/// | Parameter | Android / iOS / desktop | Web |
/// | --- | --- | --- |
/// | `spkiPins` | **required**, TLS SPKI pinning | validated, otherwise unused |
/// | `serverPublicKeys` | ignored | **required** (unless `allowUnverifiedResponses`) |
/// | `innerClient` | must be `null` | optional |
abstract final class UniversalSecurityClient {
  /// Creates an [http.Client] that verifies Ed25519 response signatures with
  /// [serverPublicKeys] on Flutter Web (browsers cannot pin TLS
  /// certificates).
  ///
  /// Throws an [ArgumentError] if [serverPublicKeys] is `null` or empty,
  /// unless [allowUnverifiedResponses] is `true`. [spkiPins] are validated but
  /// not used in browsers.
  static http.Client create({
    List<String>? spkiPins,
    List<List<int>>? serverPublicKeys,
    bool allowUnverifiedResponses = false,
    Duration timeout = const Duration(seconds: 10),
    int retryCount = 3,
    Duration retryDelay = const Duration(milliseconds: 200),
    Duration? timestampTolerance = const Duration(minutes: 5),
    int? maxResponseBytes = 10 * 1024 * 1024,
    http.Client? innerClient,
  }) {
    return HttpSecurityPinningClient(
      spkiPins ?? const [],
      serverPublicKeys: serverPublicKeys,
      allowUnverifiedResponses: allowUnverifiedResponses,
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
      timestampTolerance: timestampTolerance,
      maxResponseBytes: maxResponseBytes,
      innerClient: innerClient,
    );
  }
}
