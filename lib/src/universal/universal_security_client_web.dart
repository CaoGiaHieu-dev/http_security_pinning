// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:http/http.dart' as http;

import '../client/client_web.dart';

/// Unified cross-platform security client factory.
class UniversalSecurityClient {
  /// Creates a unified [http.Client] that uses Application-Layer Signature Pinning on Flutter Web.
  static http.Client create({
    List<String>? spkiPins,
    List<int>? serverPublicKeyBytes,
    Duration timeout = const Duration(seconds: 10),
    int retryCount = 3,
    Duration retryDelay = const Duration(milliseconds: 200),
    bool honorBadCertificateCallback = false,
    Duration timestampTolerance = const Duration(minutes: 5),
    http.Client? innerClient,
  }) {
    return HttpSecurityPinningClient(
      spkiPins ?? [],
      serverPublicKeyBytes: serverPublicKeyBytes,
      timeout: timeout,
      retryCount: retryCount,
      retryDelay: retryDelay,
      honorBadCertificateCallback: honorBadCertificateCallback,
      timestampTolerance: timestampTolerance,
      innerClient: innerClient,
    );
  }
}
