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

  private func describe(_ outcome: Any?) -> String {
    guard let error = outcome as? FlutterError else { return String(describing: outcome) }
    return "\(error.code): \(error.message ?? "")"
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
    XCTAssertNotNil(errorCode(outcome), describe(outcome))
    XCTAssertEqual(firstBytes.first, 0x16)
    XCTAssertFalse(String(decoding: firstBytes, as: UTF8.self).hasPrefix("HEAD"))
  }

  // MARK: Real proxy and server behaviour (local NWListener, no Internet)

  /// A local TCP server: it records the request head (for CONNECT), answers
  /// with `reply` (or closes at once when `reply` is nil) and, after a 200,
  /// records the first bytes sent through the tunnel (the TLS ClientHello).
  private final class FakeServer {
    let listener: NWListener
    private let queue = DispatchQueue(label: "fake-server")
    private(set) var requestHead = ""
    private(set) var tunnelBytes = Data()
    let finished: XCTestExpectation

    init(reply: String?, finished: XCTestExpectation) throws {
      // NSURLSession may retry a failed connection.
      finished.assertForOverFulfill = false
      self.finished = finished
      listener = try NWListener(using: .tcp, on: .any)
      listener.newConnectionHandler = { [weak self] connection in
        guard let self = self else { return }
        connection.start(queue: self.queue)
        guard let reply = reply else {
          connection.cancel()
          self.finished.fulfill()
          return
        }
        self.readHead(connection, buffer: Data(), reply: reply)
      }
    }

    func start(_ test: XCTestCase) {
      let ready = test.expectation(description: "listener ready")
      listener.stateUpdateHandler = { state in
        if case .ready = state { ready.fulfill() }
      }
      listener.start(queue: queue)
      test.wait(for: [ready], timeout: 5)
    }

    var port: Int { Int(listener.port!.rawValue) }

    private func readHead(_ connection: NWConnection, buffer: Data, reply: String) {
      connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, done, _ in
        var buffer = buffer
        if let data = data { buffer.append(data) }
        let text = String(decoding: buffer, as: UTF8.self)
        if text.contains("\r\n\r\n") {
          self.requestHead = text
          connection.send(content: Data("\(reply)\r\n\r\n".utf8), completion: .contentProcessed { _ in
            if reply.contains(" 200 ") {
              connection.receive(minimumIncompleteLength: 5, maximumLength: 16384) { hello, _, _, _ in
                self.tunnelBytes = hello ?? Data()
                connection.cancel()
                self.finished.fulfill()
              }
            } else {
              connection.cancel()
              self.finished.fulfill()
            }
          })
        } else if done {
          connection.cancel()
          self.finished.fulfill()
        } else {
          self.readHead(connection, buffer: buffer, reply: reply)
        }
      }
    }
  }

  /// Extracts the SNI host name from a TLS ClientHello record, if any.
  private static func serverName(inClientHello data: Data) -> String? {
    let bytes = [UInt8](data)
    func u16(_ i: Int) -> Int { Int(bytes[i]) << 8 | Int(bytes[i + 1]) }
    guard bytes.count > 43, bytes[0] == 0x16, bytes[5] == 0x01 else { return nil }
    var i = 5 + 4 + 2 + 32  // record header, handshake header, version, random
    i += 1 + Int(bytes[i])  // session id
    guard i + 2 <= bytes.count else { return nil }
    i += 2 + u16(i)  // cipher suites
    guard i + 1 <= bytes.count else { return nil }
    i += 1 + Int(bytes[i])  // compression methods
    guard i + 2 <= bytes.count else { return nil }
    let end = min(bytes.count, i + 2 + u16(i))
    i += 2
    while i + 4 <= end {
      let type = u16(i), length = u16(i + 2)
      if type == 0, i + 9 <= end {  // server_name: list length, type, name length
        let nameLength = u16(i + 7)
        guard i + 9 + nameLength <= bytes.count else { return nil }
        return String(decoding: bytes[(i + 9)..<(i + 9 + nameLength)], as: UTF8.self)
      }
      i += 4 + length
    }
    return nil
  }

  func testTheProxyTunnelCarriesConnectAndSni() throws {
    let finished = expectation(description: "tunnel used")
    let proxy = try FakeServer(reply: "HTTP/1.1 200 Connection established", finished: finished)
    proxy.start(self)
    defer { proxy.listener.cancel() }

    let outcome = call([
      "host": "service.example.test", "port": 443, "timeout": 3000,
      "proxyHost": "127.0.0.1", "proxyPort": proxy.port,
    ])
    wait(for: [finished], timeout: 5)
    // The tunnel is closed after the ClientHello: no chain, an error.
    XCTAssertNotNil(errorCode(outcome))
    XCTAssertTrue(proxy.requestHead.hasPrefix("CONNECT service.example.test:443 HTTP/1.1\r\n"),
                  proxy.requestHead)
    XCTAssertEqual(proxy.tunnelBytes.first, 0x16)
    XCTAssertEqual(Self.serverName(inClientHello: proxy.tunnelBytes), "service.example.test")
  }

  func testARefusedTunnelIsAConnectionFailure() throws {
    let finished = expectation(description: "refused")
    let proxy = try FakeServer(reply: "HTTP/1.1 502 Bad Gateway", finished: finished)
    proxy.start(self)
    defer { proxy.listener.cancel() }

    let outcome = call([
      "host": "service.example.test", "port": 443, "timeout": 3000,
      "proxyHost": "127.0.0.1", "proxyPort": proxy.port,
    ])
    wait(for: [finished], timeout: 5)
    XCTAssertNotNil(errorCode(outcome))
    XCTAssertNotEqual(errorCode(outcome), "INVALID_ARGS")
  }

  func testAServerClosingImmediatelyIsAConnectionFailure() throws {
    let finished = expectation(description: "closed")
    let server = try FakeServer(reply: nil, finished: finished)
    server.start(self)
    defer { server.listener.cancel() }

    let outcome = call(["host": "127.0.0.1", "port": server.port, "timeout": 3000])
    wait(for: [finished], timeout: 5)
    XCTAssertEqual(errorCode(outcome), "CONNECTION_FAILED", describe(outcome))
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
