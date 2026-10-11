// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'host_normalizer.dart';

/// Maps host patterns to values, with exact names taking precedence over
/// wildcards and longer wildcards over shorter ones.
///
/// * `api.example.com` matches that host only.
/// * `*.example.com` matches subdomains at any depth (`a.example.com`,
///   `a.b.example.com`) but **not** `example.com` itself.
///
/// Patterns and looked-up hosts are compared after
/// [HostNormalizer.normalize]. Bracketed IPv6 literals (`[::1]`) are
/// accepted; ports, paths, inner wildcards and whitespace are rejected with an
/// [ArgumentError].
final class HostPatternMap<T> {
  final Map<String, T> _exact = {};
  final List<({String suffix, T value})> _wildcards = [];

  /// Builds the map from [valuesByPattern].
  HostPatternMap(Map<String, T> valuesByPattern) {
    for (final entry in valuesByPattern.entries) {
      var raw = entry.key.trim();
      if (raw.startsWith('[') && raw.endsWith(']')) {
        raw = raw.substring(1, raw.length - 1); // bracketed IPv6 literal
      }
      final isWildcard = raw.startsWith('*.');
      final hostPart = isWildcard ? raw.substring(2) : raw;
      final isIpv6 = hostPart.split(':').length > 2;
      if (hostPart.isEmpty ||
          hostPart.contains('*') ||
          hostPart.startsWith('.') ||
          hostPart.contains('..') ||
          hostPart.contains('/') ||
          hostPart.contains(RegExp(r'\s')) ||
          (hostPart.contains(':') && !isIpv6) ||
          (isWildcard && isIpv6)) {
        throw ArgumentError.value(entry.key, 'host', 'Invalid host pattern');
      }
      final pattern = HostNormalizer.normalize(hostPart);
      if (!HostNormalizer.isValid(pattern) ||
          (isWildcard && RegExp(r'^[0-9.]+$').hasMatch(pattern))) {
        throw ArgumentError.value(entry.key, 'host', 'Invalid host pattern');
      }
      if (isWildcard) {
        _wildcards.add((suffix: '.$pattern', value: entry.value));
      } else {
        _exact[pattern] = entry.value;
      }
    }
    _wildcards.sort((a, b) => b.suffix.length.compareTo(a.suffix.length));
  }

  /// Whether the map has no patterns.
  bool get isEmpty => _exact.isEmpty && _wildcards.isEmpty;

  /// Returns the value for [host], or `null` if no pattern matches.
  T? lookup(String host) {
    final normalized = HostNormalizer.normalize(host);
    final exact = _exact[normalized];
    if (exact != null) return exact;
    for (final wildcard in _wildcards) {
      if (normalized.endsWith(wildcard.suffix) &&
          normalized.length > wildcard.suffix.length) {
        return wildcard.value;
      }
    }
    return null;
  }
}
