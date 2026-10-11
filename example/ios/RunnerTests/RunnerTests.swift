// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Flutter
import Network
import XCTest

import http_security_pinning

/// Native tests of the iOS certificate probe.
///
/// Run on macOS with:
///   cd example && flutter build ios --config-only --simulator
///   xcodebuild test -workspace ios/Runner.xcworkspace -scheme Runner \
///     -destination 'platform=iOS Simulator,name=iPhone 16'
class RunnerTests: XCTestCase {

  private func call(_ arguments: [String: Any?], timeout: TimeInterval = 15) -> Any? {
    let plugin = HttpSecurityPinningPlugin()
    let done = expectation(description: "result")
    var outcome: Any?
    let args = arguments.compactMapValues { $0 }
    plugin.handle(FlutterMethodCall(methodName: "fetchHostCertificates", arguments: args)) { result in
      outcome = result
      done.fulfill()
    }
    wait(for: [done], timeout: timeout)
    return outcome
  }

  private func errorCode(_ outcome: Any?) -> String? {
    (outcome as? FlutterError)?.code
  }

  func testUnknownMethodsAreNotImplemented() {
    let plugin = HttpSecurityPinningPlugin()
    let done = expectation(description: "result")
    plugin.handle(FlutterMethodCall(methodName: "other", arguments: nil)) { result in
      XCTAssertTrue((result as AnyObject) === (FlutterMethodNotImplemented as AnyObject))
      done.fulfill()
    }
    wait(for: [done], timeout: 5)
  }

  func testInvalidArgumentsAreRejected() {
    let cases: [[String: Any?]] = [
      ["port": 443, "timeout": 1000],
      ["host": "", "port": 443, "timeout": 1000],
      ["host": "example.com/evil", "port": 443, "timeout": 1000],
      ["host": "user@example.com", "port": 443, "timeout": 1000],
      ["host": "example.com", "port": 0, "timeout": 1000],
      ["host": "example.com", "port": 443, "timeout": 0],
      ["host": "example.com", "port": 443, "timeout": -1],
      ["host": "example.com", "port": 443, "timeout": 1000, "proxyHost": "proxy", "proxyPort": 0],
    ]
    for args in cases {
      XCTAssertEqual(errorCode(call(args)), "INVALID_ARGS", "\(args)")
    }
  }

  func testAnUnreachableHostFailsWithinTheDeadline() {
    let start = Date()
    let outcome = call(["host": "127.0.0.1", "port": 9, "timeout": 2000])
    let code = errorCode(outcome)
    XCTAssertTrue(code == "CONNECTION_FAILED" || code == "TIMEOUT", "\(String(describing: code))")
    XCTAssertLessThan(Date().timeIntervalSince(start), 4.5)
  }

  func testProbesRunConcurrently() {
    // 10.255.255.1 is not routable: each probe waits for its full timeout.
    let plugin = HttpSecurityPinningPlugin()
    let start = Date()
    let first = expectation(description: "first")
    let second = expectation(description: "second")
    for e in [first, second] {
      plugin.handle(FlutterMethodCall(
        methodName: "fetchHostCertificates",
        arguments: ["host": "10.255.255.1", "port": 443, "timeout": 2000])) { _ in e.fulfill() }
    }
    wait(for: [first, second], timeout: 10)
    // Serial execution would take at least 2 x 2 s.
    XCTAssertLessThan(Date().timeIntervalSince(start), 3.9)
  }

  func testTheProbeOnlySendsATlsClientHello() throws {
    // A plain TCP listener records what the probe sends: it must be a TLS
    // record (0x16), never a cleartext HTTP request.
    let listener = try NWListener(using: .tcp, on: .any)
    let received = expectation(description: "bytes")
    var firstBytes = Data()
    listener.newConnectionHandler = { connection in
      connection.start(queue: .global())
      connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
        firstBytes = data ?? Data()
        received.fulfill()
        connection.cancel()
      }
    }
    let ready = expectation(description: "ready")
    listener.stateUpdateHandler = { state in
      if case .ready = state { ready.fulfill() }
    }
    listener.start(queue: .global())
    wait(for: [ready], timeout: 5)
    defer { listener.cancel() }

    let outcome = call(["host": "127.0.0.1", "port": Int(listener.port!.rawValue), "timeout": 3000])
    wait(for: [received], timeout: 5)
    XCTAssertNotNil(errorCode(outcome))
    XCTAssertEqual(firstBytes.first, 0x16)
    XCTAssertFalse(String(decoding: firstBytes, as: UTF8.self).hasPrefix("HEAD"))
  }

  func testFetchesTheChainOfAPublicHost() throws {
    let outcome = call(["host": "www.apple.com", "port": 443, "timeout": 10000], timeout: 20)
    if let error = outcome as? FlutterError {
      throw XCTSkip("Network unavailable: \(error.code)")
    }
    let chain = try XCTUnwrap(outcome as? [FlutterStandardTypedData])
    XCTAssertGreaterThanOrEqual(chain.count, 2)
    for der in chain {
      XCTAssertNotNil(SecCertificateCreateWithData(nil, der.data as CFData))
    }
  }
}
