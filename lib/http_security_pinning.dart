/// A secure-by-default HTTP client for Dart and Flutter with certificate
/// pinning against Subject Public Key Info (SPKI) SHA-256 hashes and
/// Application-Layer Public Key Pinning on Flutter Web.
library;

export 'src/client/client.dart'
    if (dart.library.js_interop) 'src/client/client_web.dart';
export 'src/core/exceptions.dart';
export 'src/core/pin_policy.dart';
export 'src/core/presented_certificate.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/core/spki_pin.dart';
export 'src/crypto/spki_hasher.dart';
export 'src/fetcher/certificate_fetcher.dart';
export 'src/fetcher/dart_io_certificate_fetcher.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/fetcher/desktop_plugin_registrar.dart';
export 'src/service/certificate_cache.dart';
export 'src/service/pinning_service.dart'
    if (dart.library.js_interop) 'src/web/web_stub.dart';
export 'src/universal/universal_security_client.dart';
export 'src/web/exceptions.dart';
export 'src/web/payload_verifier.dart';
