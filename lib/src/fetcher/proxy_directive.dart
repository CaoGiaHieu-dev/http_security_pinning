// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:convert';

/// An HTTP proxy chosen for a certificate probe, parsed from the first entry
/// of a `findProxy` result such as `PROXY user:pass@host:8080; DIRECT`.
final class ProxyDirective {
  /// The proxy host.
  final String host;

  /// The proxy port (dart:io's default is 1080).
  final int port;

  /// `user:password` credentials embedded in the directive, if any.
  final String? userInfo;

  /// Creates a proxy directive.
  const ProxyDirective(this.host, this.port, {this.userInfo});

  /// A `Proxy-Authorization` header value for [userInfo], if any.
  String? get authorization => userInfo == null
      ? null
      : 'Basic ${base64.encode(utf8.encode(userInfo!))}';

  /// The directive in dart:io `findProxy` syntax.
  String toFindProxyString() {
    final hostPart = host.contains(':') ? '[$host]' : host;
    return 'PROXY ${userInfo == null ? '' : '$userInfo@'}$hostPart:$port';
  }

  /// Parses the first directive of [findProxyResult]. Returns `null` for
  /// `DIRECT` (or anything that is not a `PROXY` entry).
  static ProxyDirective? parse(String findProxyResult) {
    final first = findProxyResult.split(';').first.trim();
    if (!first.toUpperCase().startsWith('PROXY ')) return null;
    var target = first.substring(6).trim();
    String? userInfo;
    final at = target.lastIndexOf('@');
    if (at != -1) {
      userInfo = target.substring(0, at);
      target = target.substring(at + 1);
    }
    var host = target;
    var port = 1080;
    final colon = target.lastIndexOf(':');
    if (colon != -1 && !target.endsWith(']')) {
      host = target.substring(0, colon);
      port = int.tryParse(target.substring(colon + 1)) ?? 1080;
    }
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.substring(1, host.length - 1);
    }
    if (host.isEmpty) return null;
    return ProxyDirective(host, port, userInfo: userInfo);
  }
}
