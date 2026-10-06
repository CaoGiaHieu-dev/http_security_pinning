import 'dart:io';

void main() {
  final lcovFile = File('coverage/lcov.info');
  if (!lcovFile.existsSync()) {
    stdout.writeln('coverage/lcov.info does not exist');
    return;
  }

  final lines = lcovFile.readAsLinesSync();
  String? currentFile;
  int lf = 0;
  int lh = 0;
  int totalLf = 0;
  int totalLh = 0;
  final uncoveredMap = <String, List<int>>{};
  final statsMap = <String, ({int lh, int lf, String pct})>{};

  for (final line in lines) {
    if (line.startsWith('SF:')) {
      currentFile = line.substring(3).replaceAll('\\', '/');
      uncoveredMap[currentFile] = [];
    } else if (line.startsWith('DA:')) {
      final parts = line.substring(3).split(',');
      final lineNum = int.parse(parts[0]);
      final hitCount = int.parse(parts[1]);
      if (hitCount == 0 && currentFile != null) {
        uncoveredMap[currentFile]!.add(lineNum);
      }
    } else if (line.startsWith('LF:')) {
      lf = int.parse(line.substring(3));
      totalLf += lf;
    } else if (line.startsWith('LH:')) {
      lh = int.parse(line.substring(3));
      totalLh += lh;
      final pct = lf > 0 ? (lh / lf * 100).toStringAsFixed(1) : '0';
      if (currentFile != null) {
        statsMap[currentFile] = (lh: lh, lf: lf, pct: pct);
      }
    }
  }

  stdout.writeln('=== TEST COVERAGE REPORT ===');
  for (final entry in statsMap.entries) {
    stdout.writeln(
        '${entry.key.padRight(45)}: ${entry.value.lh} / ${entry.value.lf} (${entry.value.pct}%)');
    final unc = uncoveredMap[entry.key] ?? [];
    if (unc.isNotEmpty) {
      stdout.writeln('   Uncovered lines: ${unc.join(', ')}');
    }
  }
  final totalPct =
      totalLf > 0 ? (totalLh / totalLf * 100).toStringAsFixed(1) : '0';
  stdout.writeln('--------------------------------------------------');
  stdout.writeln('TOTAL: $totalLh / $totalLf ($totalPct%)');
}
