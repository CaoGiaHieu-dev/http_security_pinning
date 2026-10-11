// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

/// Every base64 pin written in the docs, the example and the integration
/// tests must be a valid pin: an invalid placeholder makes the snippet or the
/// test fail at runtime with an InvalidPinException.
void main() {
  test('placeholder pins in docs and examples are valid', () {
    final pin = RegExp(r"'([A-Za-z0-9+/]{43}=)'");
    const files = [
      'README.md',
      'example/lib/main.dart',
      'example/integration_test/pinning_test.dart',
    ];
    var count = 0;
    for (final file in files) {
      for (final match in pin.allMatches(File(file).readAsStringSync())) {
        expect(() => SpkiPin.parse(match.group(1)!), returnsNormally,
            reason: '${match.group(1)} in $file');
        count++;
      }
    }
    expect(count, greaterThan(5));
  });
}
