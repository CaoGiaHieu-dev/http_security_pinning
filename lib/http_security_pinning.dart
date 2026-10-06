/// A secure-by-default HTTP client for Dart and Flutter with certificate
/// pinning against Subject Public Key Info (SPKI) SHA-256 hashes.
library;

// Client facade
export 'src/client/client.dart'
    if (dart.library.js_interop) 'src/client/client_stub.dart';

// Core models, policies, and exceptions
export 'src/core/exceptions.dart';
export 'src/core/pin_policy.dart';
export 'src/core/presented_certificate.dart'
    if (dart.library.js_interop) 'src/client/client_stub.dart';
export 'src/core/spki_pin.dart';

// Cryptographic SPKI extraction
export 'src/crypto/spki_hasher.dart';

// Handshake fetchers
export 'src/fetcher/certificate_fetcher.dart';
export 'src/fetcher/dart_io_certificate_fetcher.dart'
    if (dart.library.js_interop) 'src/client/client_stub.dart';
export 'src/fetcher/desktop_plugin_registrar.dart';

// Service & caching
export 'src/service/certificate_cache.dart';
export 'src/service/pinning_service.dart';
