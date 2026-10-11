// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Plugin entry point required by Flutter's plugin registration on Windows,
/// Linux and macOS (`dartPluginClass` in pubspec.yaml).
///
/// It does nothing: on desktop the certificate probe is implemented in pure
/// Dart (`DartIoCertificateFetcher`), so there is nothing to register. Apps
/// never need to use this class.
class HttpSecurityPinningPlugin {
  /// Default constructor for [HttpSecurityPinningPlugin].
  const HttpSecurityPinningPlugin();

  /// Called by the generated plugin registrant; intentionally empty.
  static void registerWith() {}
}
