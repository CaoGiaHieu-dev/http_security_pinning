// Copyright (c) 2025-2026 Cao Gia Hiếu <caogiahieu99@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Compiles every ```dart snippet of README.md against this package, so that
// the documentation cannot drift from the API.
//
//   dart run tool/check_readme_snippets.dart [path/to/README.md]
//
// Each snippet must be a complete Dart file (imports included). The snippets
// are written to a temporary Flutter package that depends on this one and
// analyzed with `flutter analyze`; errors and warnings fail the check.

import 'dart:io';

Future<void> main(List<String> args) async {
  final root = File.fromUri(Platform.script).parent.parent;
  final readme = File(args.isNotEmpty ? args.first : '${root.path}/README.md')
      .readAsStringSync();
  final snippets = RegExp(r'```dart\r?\n([\s\S]*?)```')
      .allMatches(readme)
      .map((m) => m.group(1)!)
      .toList();
  if (snippets.isEmpty) {
    stderr.writeln('No Dart snippets found in README.md');
    exit(1);
  }

  final temp = Directory.systemTemp.createTempSync('readme_snippets_');
  try {
    final packagePath = root.absolute.path.replaceAll(r'\', '/');
    File('${temp.path}/pubspec.yaml').writeAsStringSync('''
name: readme_snippets
publish_to: none
environment:
  sdk: ">=3.5.0 <4.0.0"
dependencies:
  flutter:
    sdk: flutter
  dio: ^5.4.0
  http: ^1.2.0
  http_security_pinning:
    path: $packagePath
''');
    File('${temp.path}/analysis_options.yaml').writeAsStringSync('''
analyzer:
  errors:
    avoid_print: ignore
''');
    Directory('${temp.path}/lib').createSync();
    for (var i = 0; i < snippets.length; i++) {
      File('${temp.path}/lib/snippet_$i.dart').writeAsStringSync(snippets[i]);
    }

    final flutter = Platform.isWindows ? 'flutter.bat' : 'flutter';
    final get = await Process.run(flutter, ['pub', 'get'],
        workingDirectory: temp.path, runInShell: true);
    if (get.exitCode != 0) {
      stderr
        ..writeln(get.stdout)
        ..writeln(get.stderr);
      exitCode = get.exitCode;
      return;
    }
    final analyze = await Process.run(
      flutter,
      ['analyze', '--no-fatal-infos', 'lib'],
      workingDirectory: temp.path,
      runInShell: true,
    );
    stdout.writeln(analyze.stdout);
    if (analyze.exitCode != 0) {
      stderr
        ..writeln(analyze.stderr)
        ..writeln('README snippets do not compile (see lib/snippet_N.dart '
            'numbering: N is the index of the ```dart block).');
      exitCode = analyze.exitCode;
      return;
    }
    stdout.writeln('${snippets.length} README snippets compile.');
  } finally {
    try {
      temp.deleteSync(recursive: true);
    } on FileSystemException {
      // The analysis server may still hold files on Windows; leave it to the
      // OS temp cleanup.
    }
  }
}
