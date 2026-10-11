// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

import '../client/client.dart';

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
  /// Creates an [http.Client] that enforces TLS SPKI pinning with [spkiPins]
  /// on Android, iOS, Windows, macOS and Linux.
  ///
  /// Throws an [ArgumentError] if [spkiPins] is `null` or empty (that would
  /// silently disable pinning) or if [innerClient] is given (Web only).
  ///
  /// [serverPublicKeys], [allowUnverifiedResponses], [timestampTolerance]
  /// and [maxResponseBytes] configure the Web response-signature check and
  /// are ignored on this platform.
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
    if (spkiPins == null || spkiPins.isEmpty) {
      throw ArgumentError.value(
        spkiPins,
        'spkiPins',
        'must not be empty on Android, iOS and desktop; without pins the '
            'client would not pin anything',
      );
    }
    if (innerClient != null) {
      throw ArgumentError.value(
        innerClient,
        'innerClient',
        'is only supported on Flutter Web',
      );
    }
    return IOClient(
      HttpSecurityPinningClient(
        spkiPins,
        timeout: timeout,
        retryCount: retryCount,
        retryDelay: retryDelay,
      ),
    );
  }
}
