// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:flutter/foundation.dart';

import 'exceptions.dart';
import 'host_normalizer.dart';
import 'host_pattern_map.dart';
import 'spki_pin.dart';

/// Defines which SPKI pins apply to which host.
///
/// Host names are compared after [HostNormalizer.normalize], so letter case,
/// a trailing dot and Unicode vs. punycode spellings do not matter.
abstract interface class PinPolicy {
  /// Returns the set of valid pins for [host], or `null` if the host is
  /// unpinned (only possible when [allowUnpinnedHosts] is `true`).
  ///
  /// Throws [UnpinnedHostException] if the policy forbids unpinned hosts and
  /// [host] has no match.
  Set<SpkiPin>? pinsFor(String host);

  /// Whether requests to hosts without configured pins are allowed.
  bool get allowUnpinnedHosts;

  /// A policy that applies the same [pins] to every host.
  ///
  /// Throws an [ArgumentError] if [pins] is empty: an empty pin set would
  /// silently disable pinning.
  factory PinPolicy.uniform(Iterable<SpkiPin> pins) = _UniformPolicy;

  /// A policy with per-host configurations, supporting exact matches
  /// (e.g. `api.example.com`) and wildcard patterns (e.g. `*.example.com`).
  ///
  /// A wildcard matches subdomains at any depth (`a.example.com`,
  /// `a.b.example.com`) but **not** the bare domain (`example.com`); add the
  /// bare domain as its own entry if it needs pinning too.
  ///
  /// Throws an [ArgumentError] for an invalid pattern or an empty pin list.
  factory PinPolicy.perHost(
    Map<String, Iterable<SpkiPin>> pinsByHost, {
    bool allowUnpinnedHosts,
  }) = _PerHostPolicy;
}

void _warnIfNoBackupPin(String scope, Set<SpkiPin> pins) {
  if (kDebugMode && pins.length < 2) {
    debugPrint(
      'HttpSecurityPinning: only one pin is configured for $scope. Configure '
      'at least one backup pin (ideally the SPKI hash of a key that is not '
      'deployed yet) so that a key rotation does not lock users out.',
    );
  }
}

class _UniformPolicy implements PinPolicy {
  final Set<SpkiPin> _pins;

  _UniformPolicy(Iterable<SpkiPin> pins) : _pins = Set.unmodifiable(pins) {
    if (_pins.isEmpty) {
      throw ArgumentError.value(
        pins,
        'pins',
        'must not be empty; an empty pin set would disable pinning',
      );
    }
    _warnIfNoBackupPin('all hosts', _pins);
  }

  @override
  bool get allowUnpinnedHosts => false;

  @override
  Set<SpkiPin> pinsFor(String host) => _pins;
}

class _PerHostPolicy implements PinPolicy {
  final HostPatternMap<Set<SpkiPin>> _pins;

  @override
  final bool allowUnpinnedHosts;

  _PerHostPolicy(
    Map<String, Iterable<SpkiPin>> pinsByHost, {
    this.allowUnpinnedHosts = false,
  }) : _pins = HostPatternMap(pinsByHost.map((host, pins) {
          final pinSet = Set<SpkiPin>.unmodifiable(pins);
          if (pinSet.isEmpty) {
            throw ArgumentError.value(
                host, 'pins', 'Pin list must not be empty');
          }
          _warnIfNoBackupPin(host, pinSet);
          return MapEntry(host, pinSet);
        })) {
    if (_pins.isEmpty && !allowUnpinnedHosts) {
      throw ArgumentError.value(
        pinsByHost,
        'pinsByHost',
        'must not be empty unless allowUnpinnedHosts is true',
      );
    }
  }

  @override
  Set<SpkiPin>? pinsFor(String host) {
    final pins = _pins.lookup(host);
    if (pins != null) return pins;
    if (allowUnpinnedHosts) return null;
    throw UnpinnedHostException(host);
  }
}
