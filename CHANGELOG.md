## 1.0.1

* Fix android namespace

## 1.0.0

* Initial public release of the `http_security_pinning` package.

**Features**

* **SPKI Pinning**: Provides an `HttpClient` implementation that enforces certificate pinning against SPKI hashes to prevent MITM attacks.
* **Easy Integration**: Works seamlessly with popular packages like `http` and `dio`.
* **Configurable**: Set custom `timeout` and `retryCount` for the certificate fetching process.
* **Global Configuration**: Optionally apply pinning to all `HttpClient` instances in your app using `HttpOverrides`.
* **Robust Error Handling**: Provides clear, catchable exceptions (`CertificateFetchException`, `NoValidPinsFoundException`) for pinning failures.
* **Automatic Hash Logging**: Logs the certificate chain's SPKI hashes to the console to simplify setup.
* **Comprehensive Testing**: Includes a full integration test suite.
* **Full Documentation**: Includes a detailed README, API documentation, and a complete example app.
* **Platform Support**: Supports Android (API 19+) and iOS (10.0+).