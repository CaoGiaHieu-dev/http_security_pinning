// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'exceptions.dart';
import 'spki_pin.dart';

/// Defines which SPKI pins apply to which host.
abstract interface class PinPolicy {
  /// Returns the set of valid pins for [host], or `null` if the host is
  /// unpinned.
  ///
  /// Throws [UnpinnedHostException] if the policy forbids unpinned hosts and
  /// [host] has no match.
  Set<SpkiPin>? pinsFor(String host);

  /// Whether requests to hosts without configured pins are allowed.
  bool get allowUnpinnedHosts;

  /// A policy that applies the same [pins] to every host.
  factory PinPolicy.uniform(Iterable<SpkiPin> pins) = _UniformPolicy;

  /// A policy with per-host configurations, supporting exact matches
  /// (e.g. `api.example.com`) and wildcard patterns (e.g. `*.example.com`).
  factory PinPolicy.perHost(
    Map<String, Iterable<SpkiPin>> pinsByHost, {
    bool allowUnpinnedHosts,
  }) = _PerHostPolicy;
}

class _UniformPolicy implements PinPolicy {
  final Set<SpkiPin> _pins;

  _UniformPolicy(Iterable<SpkiPin> pins) : _pins = pins.toSet();

  @override
  bool get allowUnpinnedHosts => false;

  @override
  Set<SpkiPin>? pinsFor(String host) => _pins.isEmpty ? null : _pins;
}

class _PerHostPolicy implements PinPolicy {
  final Map<String, Set<SpkiPin>> _exact = {};
  final List<({String suffix, Set<SpkiPin> pins})> _wildcards = [];

  @override
  final bool allowUnpinnedHosts;

  _PerHostPolicy(
    Map<String, Iterable<SpkiPin>> pinsByHost, {
    this.allowUnpinnedHosts = false,
  }) {
    for (final entry in pinsByHost.entries) {
      final pattern = entry.key.trim().toLowerCase();
      if (pattern.isEmpty ||
          pattern == '*' ||
          (pattern.contains('*') && !pattern.startsWith('*.')) ||
          pattern.indexOf('*', 2) != -1) {
        throw ArgumentError.value(entry.key, 'host', 'Invalid host pattern');
      }
      final pinSet = entry.value.toSet();
      if (pinSet.isEmpty) {
        throw ArgumentError.value(
            entry.key, 'pins', 'Pin list must not be empty');
      }

      if (pattern.startsWith('*.')) {
        // e.g. '*.example.com' -> suffix '.example.com'
        _wildcards.add((suffix: pattern.substring(1), pins: pinSet));
      } else {
        _exact[pattern] = pinSet;
      }
    }
    // Sort wildcards by longest suffix first for most specific match
    _wildcards.sort((a, b) => b.suffix.length.compareTo(a.suffix.length));
  }

  @override
  Set<SpkiPin>? pinsFor(String host) {
    final lowerHost = host.trim().toLowerCase();

    // 1. Exact match has highest priority
    final exact = _exact[lowerHost];
    if (exact != null) return exact;

    // 2. Wildcard matches (longest suffix first)
    for (final wildcard in _wildcards) {
      if (lowerHost.endsWith(wildcard.suffix) &&
          lowerHost.length > wildcard.suffix.length) {
        return wildcard.pins;
      }
    }

    // 3. Fallback: unpinned host
    if (allowUnpinnedHosts) return null;
    throw UnpinnedHostException(host);
  }
}
