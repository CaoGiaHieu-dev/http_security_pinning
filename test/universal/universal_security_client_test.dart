// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:flutter_test/flutter_test.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  group('UniversalSecurityClient Tests', () {
    test('creates a functional client instance on current platform', () {
      final client = UniversalSecurityClient.create(
        spkiPins: ['6CyxBXGxfRqVy8AsRAT86co7plxc2K9B83J1bTyUqTY='],
      );
      expect(client, isNotNull);
      client.close();
    });
  });
}
