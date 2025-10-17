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
        primarySwatch: Colors.blue,
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
  final _pinController = TextEditingController(
    text:
        'e4wu8h9eLNeNUg6cVb5gGWM0PsiM9M3i3E32qKOkBwY=', // Correct pin for github.com
  );
  final _timeoutController = TextEditingController(text: '10');
  final _retryCountController = TextEditingController(text: '2');

  String _result = 'Ready to make a request.';
  bool _isLoading = false;

  Future<void> _makeRequestWithHttp() async {
    _executeRequest(() async {
      final client = IOClient(
        HttpSecurityPinningClient(
          _getHashes(),
          timeout: _getTimeout(),
          retryCount: _getRetryCount(),
        ),
      );

      final response = await client.get(Uri.parse(_urlController.text));
      return 'SUCCESS with http!\nStatus code: ${response.statusCode}\nBody length: ${response.body.length}';
    });
  }

  Future<void> _makeRequestWithDio() async {
    _executeRequest(() async {
      final dio = Dio();
      (dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
        return HttpSecurityPinningClient(
          _getHashes(),
          timeout: _getTimeout(),
          retryCount: _getRetryCount(),
        );
      };

      final response = await dio.get(_urlController.text);
      return 'SUCCESS with dio!\nStatus code: ${response.statusCode}\nData length: ${response.data.toString().length}';
    });
  }

  Future<void> _executeRequest(Future<String> Function() request) async {
    if (_isLoading) return;

    setState(() {
      _isLoading = true;
      _result = 'Loading...';
    });

    try {
      final result = await request();
      setState(() {
        _result = result;
      });
    } catch (e) {
      setState(() {
        _result = 'ERROR:\n$e';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  List<String> _getHashes() {
    final text = _pinController.text.trim();
    if (text.isEmpty) return [];
    return text.split(',').map((e) => e.trim()).toList();
  }

  Duration _getTimeout() =>
      Duration(seconds: int.tryParse(_timeoutController.text) ?? 10);

  int _getRetryCount() => int.tryParse(_retryCountController.text) ?? 3;

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
                labelText: 'SPKI SHA-256 Pins (comma-separated)',
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
                    decoration: const InputDecoration(labelText: 'Retry Count'),
                    keyboardType: TextInputType.number,
                    inputFormatters: [FilteringTextInputFormatter.digitsOnly],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            ElevatedButton(
              onPressed: _isLoading ? null : _makeRequestWithHttp,
              child: const Text('Make Request with http'),
            ),
            const SizedBox(height: 12),
            ElevatedButton(
              onPressed: _isLoading ? null : _makeRequestWithDio,
              child: const Text('Make Request with dio'),
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
                child: SingleChildScrollView(child: Text(_result)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
