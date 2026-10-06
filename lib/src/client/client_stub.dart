/// A stub implementation of [HttpSecurityPinningClient] for Flutter Web.
///
/// Certificate pinning cannot be performed on the Web because browsers handle
/// the TLS handshake internally inside the sandbox and do not allow web apps
/// to inspect or override certificate validation.
class HttpSecurityPinningClient {
  /// Whether certificate pinning is supported on the current platform.
  ///
  /// Always returns `false` on Flutter Web.
  static bool get isSupported => false;

  /// Clears the cache (no-op on web).
  static void clearCache() {}

  /// Creates a stub client that throws [UnsupportedError] when used on the Web.
  HttpSecurityPinningClient(
    List<String> spkiHashes, {
    dynamic timeout,
    dynamic retryCount,
    dynamic retryDelay,
    dynamic honorBadCertificateCallback,
    dynamic pinningService,
  }) {
    throw UnsupportedError(
      'HttpSecurityPinningClient is not supported on Flutter Web. '
      'Web browsers manage TLS certificates internally and do not allow custom certificate pinning.',
    );
  }

  /// Creates a stub client that throws [UnsupportedError] when used on the Web.
  HttpSecurityPinningClient.perHost(
    Map<String, List<String>> pinsByHost, {
    dynamic allowUnpinnedHosts,
    dynamic timeout,
    dynamic retryCount,
    dynamic retryDelay,
    dynamic honorBadCertificateCallback,
    dynamic pinningService,
  }) {
    throw UnsupportedError(
      'HttpSecurityPinningClient is not supported on Flutter Web. '
      'Web browsers manage TLS certificates internally and do not allow custom certificate pinning.',
    );
  }
}
