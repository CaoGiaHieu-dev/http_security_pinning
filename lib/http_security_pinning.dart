// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// A secure-by-default HTTP client for Flutter with TLS certificate pinning
/// against Subject Public Key Info (SPKI) SHA-256 hashes on Android, iOS,
/// Windows, macOS and Linux, and Ed25519 response-signature verification on
/// Flutter Web (where browsers do not allow TLS pinning).
library;

export 'src/client/client.dart'
    if (dart.library.js_interop) 'src/client/client_web.dart';
export 'src/core/exceptions.dart';
export 'src/core/host_normalizer.dart';
export 'src/core/host_pattern_map.dart';
export 'src/core/pin_policy.dart';
export 'src/core/presented_certificate.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/core/spki_pin.dart';
export 'src/crypto/spki_hasher.dart';
export 'src/fetcher/certificate_fetcher.dart';
export 'src/fetcher/dart_io_certificate_fetcher.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/fetcher/desktop_plugin_registrar.dart';
export 'src/fetcher/proxy_directive.dart';
export 'src/service/certificate_cache.dart';
export 'src/service/pinning_service.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/universal/universal_security_client.dart';
export 'src/web/exceptions.dart';
export 'src/web/payload_verifier.dart';
export 'src/web/response_signer.dart';
export 'src/web/signature_base.dart';
