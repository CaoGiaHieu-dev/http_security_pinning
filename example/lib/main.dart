// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'package:dio/dio.dart';
import 'package:dio/io.dart' show IOHttpClientAdapter;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/io_client.dart';
import 'package:http_security_pinning/http_security_pinning.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Http Security Pinning Example',
      theme: ThemeData(
        colorSchemeSeed: Colors.blue,
        useMaterial3: true,
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: const PinningHomePage(),
    );
  }
}

class PinningHomePage extends StatefulWidget {
  const PinningHomePage({super.key});

  @override
  State<PinningHomePage> createState() => _PinningHomePageState();
}

class _PinningHomePageState extends State<PinningHomePage> {
  final _urlController = TextEditingController(text: 'https://github.com');
  // Pins change whenever a server rotates its keys: use "Discover pins" to
  // read the current ones. Always configure at least two (primary + backup).
  final _pinController = TextEditingController();
  final _timeoutController = TextEditingController(text: '10');
  final _retryCountController = TextEditingController(text: '2');

  /// A syntactically valid pin that matches no real key; used to discover
  /// the pins a server presents.
  static const _discoveryPin = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  String _result = 'Discover the pins of a host, then make a pinned request.';
  bool _isLoading = false;

  @override
  void dispose() {
    _urlController.dispose();
    _pinController.dispose();
    _timeoutController.dispose();
    _retryCountController.dispose();
    super.dispose();
  }

  Future<void> _discoverPins() async {
    await _executeRequest(() async {
      final client = HttpSecurityPinningClient([_discoveryPin]);
      try {
        await (await client.getUrl(Uri.parse(_urlController.text))).close();
        return 'Unexpected: the discovery pin matched.';
      } on NoValidPinsFoundException catch (e) {
        _pinController.text = e.observedPins.join(', ');
        return 'Pins presented by ${e.host} (leaf first):\n'
            '${e.observedPins.join('\n')}\n\n'
            'Verify them out of band (e.g. with openssl) before shipping them, '
            'and add a backup pin for a key you control.';
      } finally {
        client.close(force: true);
      }
    });
  }

  Future<void> _makeRequestWithHttp() async {
    await _executeRequest(() async {
      final client = IOClient(
        HttpSecurityPinningClient(
          _getHashes(),
          timeout: _getTimeout(),
          retryCount: _getRetryCount(),
        ),
      );
      try {
        final response = await client.get(Uri.parse(_urlController.text));
        return 'SUCCESS with http!\nStatus code: ${response.statusCode}\n'
            'Body length: ${response.body.length}';
      } finally {
        client.close();
      }
    });
  }

  Future<void> _makeRequestWithDio() async {
    await _executeRequest(() async {
      final pins = _getHashes();
      final dio = Dio();
      (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
        return HttpSecurityPinningClient(
          pins,
          timeout: _getTimeout(),
          retryCount: _getRetryCount(),
        );
      };
      try {
        final response = await dio.get<String>(_urlController.text);
        return 'SUCCESS with dio!\nStatus code: ${response.statusCode}\n'
            'Data length: ${response.data?.length ?? 0}';
      } on DioException catch (e) {
        // Dio wraps errors; the pinning exception is in `error`.
        throw e.error ?? e;
      } finally {
        dio.close(force: true);
      }
    });
  }

  Future<void> _executeRequest(Future<String> Function() request) async {
    if (_isLoading) return;

    setState(() {
      _isLoading = true;
      _result = 'Loading...';
    });

    String result;
    try {
      result = await request();
    } on ArgumentError catch (e) {
      result = 'CONFIGURATION ERROR:\n${e.message}';
    } catch (e) {
      result = 'ERROR:\n$e';
    }
    if (!mounted) return;
    setState(() {
      _result = result;
      _isLoading = false;
    });
  }

  List<String> _getHashes() => _pinController.text
      .split(',')
      .map((e) => e.trim())
      .where((e) => e.isNotEmpty)
      .toList();

  Duration _getTimeout() =>
      Duration(seconds: int.tryParse(_timeoutController.text) ?? 10);

  int _getRetryCount() => int.tryParse(_retryCountController.text) ?? 2;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Http Security Pinning')),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            TextField(
              controller: _urlController,
              decoration: const InputDecoration(labelText: 'URL'),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _pinController,
              decoration: const InputDecoration(
                labelText: 'SPKI SHA-256 pins (comma-separated, at least two)',
              ),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _timeoutController,
                    decoration: const InputDecoration(
                      labelText: 'Timeout (sec)',
                    ),
                    keyboardType: TextInputType.number,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: TextField(
                    controller: _retryCountController,
                    decoration: const InputDecoration(labelText: 'Retry count'),
                    keyboardType: TextInputType.number,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            OutlinedButton(
              onPressed: _isLoading ? null : _discoverPins,
              child: const Text('Discover pins'),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isLoading ? null : _makeRequestWithHttp,
              child: const Text('Make request with http'),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isLoading ? null : _makeRequestWithDio,
              child: const Text('Make request with dio'),
            ),
            const SizedBox(height: 24),
            Text('Result:', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 8),
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(8.0),
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.grey.shade400),
                  borderRadius: BorderRadius.circular(8.0),
                ),
                child: SingleChildScrollView(child: SelectableText(_result)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
