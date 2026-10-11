// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Normalizes host names so that pin policies and caches compare them the
/// same way the network stack resolves them.
abstract final class HostNormalizer {
  /// Returns the canonical form of [host]:
  ///
  /// * percent-encoding (as produced by [Uri] for non-ASCII hosts) is decoded
  ///   (a value that is not valid UTF-8 is kept as is, and [isValid] rejects
  ///   it),
  /// * the host is lower-cased and surrounding whitespace is removed,
  /// * a single trailing dot (`example.com.`) is removed, and
  /// * internationalized labels are converted to their ASCII (punycode,
  ///   `xn--`) form.
  ///
  /// * IP literals are written in one canonical form: every IPv4 spelling the
  ///   system resolver accepts (`127.1`, `2130706433`, `0x7f.0.0.1`) becomes
  ///   dotted decimal, IPv4-mapped IPv6 (`::ffff:127.0.0.1`) becomes IPv4,
  ///   and IPv6 is compressed as in RFC 5952 (`0:0:0:0:0:0:0:1` → `::1`).
  ///
  /// `api.Example.com.`, `api.example.com` and `API.EXAMPLE.COM` therefore all
  /// normalize to `api.example.com`, and `bücher.de` to `xn--bcher-kva.de`.
  ///
  /// Use [isValid] on the result before using it as a network host.
  static String normalize(String host) {
    var value = host.trim();
    // Hosts longer than any valid DNS name are returned as they are (and
    // rejected by isValid) before any costly processing: punycode encoding
    // is quadratic in the label length.
    if (value.length > _maxRawLength) return value;
    if (value.startsWith('[') && value.endsWith(']')) {
      value = value.substring(1, value.length - 1);
    }
    if (value.contains('%')) {
      try {
        value = Uri.decodeComponent(value);
      } on ArgumentError {
        // Keep the raw value; isValid() rejects it.
      } on FormatException {
        // Invalid UTF-8 after decoding: keep the raw value; isValid() rejects
        // it.
      }
    }
    value = value.toLowerCase();
    if (value.endsWith('.') && value.length > 1) {
      value = value.substring(0, value.length - 1);
    }
    if (!_isAscii(value)) {
      final labels = value.split('.');
      if (value.length > 253 || labels.any((l) => l.length > 63)) {
        return value;
      }
      value = labels.map(_labelToAscii).join('.');
    }
    return _canonicalIpv6(value) ?? _canonicalIpv4(value) ?? value;
  }

  // 253 characters, each percent-encoded as up to 12 bytes of UTF-8.
  static const int _maxRawLength = 253 * 12;

  static final RegExp _hostName =
      RegExp(r'^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$');
  static final RegExp _ipv6 = RegExp(r'^[0-9a-f:.]+$');

  /// Whether a [normalize]d host only contains characters that are valid in
  /// a DNS name or an IP literal (no whitespace, control characters, `%`,
  /// `/`, `@`, ...).
  static bool isValid(String normalizedHost) =>
      normalizedHost.isNotEmpty &&
      normalizedHost.length <= 253 &&
      (_hostName.hasMatch(normalizedHost) ||
          (normalizedHost.contains(':') && _ipv6.hasMatch(normalizedHost)));

  static final RegExp _numericIpv4 =
      RegExp(r'^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}$');

  /// Parses IPv4 spellings accepted by `inet_aton` (decimal, octal with a
  /// leading `0`, hexadecimal with `0x`, 1 to 4 parts).
  static String? _canonicalIpv4(String value) {
    if (!_numericIpv4.hasMatch(value)) return null;
    final parts = <int>[];
    for (final part in value.split('.')) {
      final int? parsed;
      if (part.startsWith('0x')) {
        parsed =
            part.length == 2 ? 0 : int.tryParse(part.substring(2), radix: 16);
      } else if (part.length > 1 && part.startsWith('0')) {
        parsed = int.tryParse(part.substring(1), radix: 8);
      } else {
        parsed = int.tryParse(part);
      }
      if (parsed == null || parsed < 0) return null;
      parts.add(parsed);
    }
    final last = parts.removeLast();
    if (parts.any((p) => p > 255)) return null;
    final lastBytes = 4 - parts.length;
    if (last >= (1 << (8 * lastBytes))) return null;
    final bytes = [
      ...parts,
      for (var i = lastBytes - 1; i >= 0; i--) (last >> (8 * i)) & 0xff,
    ];
    return bytes.join('.');
  }

  static String? _canonicalIpv6(String value) {
    if (!value.contains(':') || !_ipv6.hasMatch(value)) return null;
    final List<int> bytes;
    try {
      bytes = Uri.parseIPv6Address(value);
    } on FormatException {
      return null;
    }
    final mapped = bytes.sublist(0, 10).every((b) => b == 0) &&
        bytes[10] == 0xff &&
        bytes[11] == 0xff;
    if (mapped) return bytes.sublist(12).join('.');

    final groups = [
      for (var i = 0; i < 16; i += 2) (bytes[i] << 8) | bytes[i + 1],
    ];
    // Longest run of at least two zero groups (the first one on a tie).
    var bestStart = -1, bestLength = 1;
    for (var i = 0; i < 8;) {
      if (groups[i] != 0) {
        i++;
        continue;
      }
      var j = i;
      while (j < 8 && groups[j] == 0) {
        j++;
      }
      if (j - i > bestLength) {
        bestStart = i;
        bestLength = j - i;
      }
      i = j;
    }
    String hex(Iterable<int> g) => g.map((x) => x.toRadixString(16)).join(':');
    if (bestStart == -1) return hex(groups);
    return '${hex(groups.sublist(0, bestStart))}::'
        '${hex(groups.sublist(bestStart + bestLength))}';
  }

  static bool _isAscii(String s) => s.codeUnits.every((c) => c < 0x80);

  static String _labelToAscii(String label) =>
      _isAscii(label) ? label : 'xn--${_punycodeEncode(label)}';

  // Punycode (RFC 3492) parameters.
  static const int _base = 36;
  static const int _tMin = 1;
  static const int _tMax = 26;
  static const int _skew = 38;
  static const int _damp = 700;
  static const int _initialBias = 72;
  static const int _initialN = 128;

  static String _punycodeEncode(String input) {
    final codePoints = input.runes.toList();
    final output = StringBuffer();
    for (final c in codePoints) {
      if (c < 0x80) output.writeCharCode(c);
    }
    final basicCount = output.length;
    var handled = basicCount;
    if (basicCount > 0) output.write('-');

    var n = _initialN;
    var delta = 0;
    var bias = _initialBias;

    while (handled < codePoints.length) {
      var m = 0x10FFFF + 1;
      for (final c in codePoints) {
        if (c >= n && c < m) m = c;
      }
      delta += (m - n) * (handled + 1);
      n = m;
      for (final c in codePoints) {
        if (c < n) delta++;
        if (c == n) {
          var q = delta;
          for (var k = _base;; k += _base) {
            final t =
                k <= bias ? _tMin : (k >= bias + _tMax ? _tMax : k - bias);
            if (q < t) break;
            output.writeCharCode(_digit(t + (q - t) % (_base - t)));
            q = (q - t) ~/ (_base - t);
          }
          output.writeCharCode(_digit(q));
          bias = _adapt(delta, handled + 1, handled == basicCount);
          delta = 0;
          handled++;
        }
      }
      delta++;
      n++;
    }
    return output.toString();
  }

  static int _adapt(int delta, int numPoints, bool firstTime) {
    var d = firstTime ? delta ~/ _damp : delta ~/ 2;
    d += d ~/ numPoints;
    var k = 0;
    while (d > ((_base - _tMin) * _tMax) ~/ 2) {
      d ~/= _base - _tMin;
      k += _base;
    }
    return k + ((_base - _tMin + 1) * d) ~/ (d + _skew);
  }

  static int _digit(int d) => d < 26 ? 0x61 + d : 0x30 + (d - 26);
}
