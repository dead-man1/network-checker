import 'package:flutter/foundation.dart';
import '../../../core/services/ech_service.dart';

class AddEchController extends ChangeNotifier {
  String _inputText = '';
  String get inputText => _inputText;

  String _echConfigList = EchService.defaultEchConfigList;
  String get echConfigList => _echConfigList;

  int _socksPort = 10808;
  int get socksPort => _socksPort;

  int? _httpPort = 10809;
  int? get httpPort => _httpPort;

  String _dnsServer = EchService.defaultDnsServer;
  String get dnsServer => _dnsServer;

  String _domesticDns = EchService.defaultDomesticDns;
  String get domesticDns => _domesticDns;

  String _remarkSuffix = '-ech';
  String get remarkSuffix => _remarkSuffix;

  String _fingerprint = 'chrome';
  String get fingerprint => _fingerprint;

  String _alpnText = 'http/1.1';
  String get alpnText => _alpnText;

  bool _allowInsecure = false;
  bool get allowInsecure => _allowInsecure;

  List<EchResult> _results = [];
  List<EchResult> get results => _results;

  int _selectedIndex = 0;
  int get selectedIndex => _selectedIndex;

  EchResult? get currentResult =>
      (_results.isNotEmpty && _selectedIndex >= 0 && _selectedIndex < _results.length)
          ? _results[_selectedIndex]
          : null;

  String? _errorMessage;
  String? get errorMessage => _errorMessage;

  bool _isProcessing = false;
  bool get isProcessing => _isProcessing;

  void setInputText(String value) {
    _inputText = value;
    _errorMessage = null;
    notifyListeners();
  }

  void setEchConfigList(String value) {
    _echConfigList = value.trim();
    notifyListeners();
  }

  void setSocksPort(int value) {
    _socksPort = value;
    notifyListeners();
  }

  void setHttpPort(int? value) {
    _httpPort = value;
    notifyListeners();
  }

  void setDnsServer(String value) {
    _dnsServer = value.trim();
    notifyListeners();
  }

  void setDomesticDns(String value) {
    _domesticDns = value.trim();
    notifyListeners();
  }

  void setRemarkSuffix(String value) {
    _remarkSuffix = value;
    notifyListeners();
  }

  void setFingerprint(String value) {
    _fingerprint = value;
    notifyListeners();
  }

  void setAlpnText(String value) {
    _alpnText = value;
    notifyListeners();
  }

  void setAllowInsecure(bool value) {
    _allowInsecure = value;
    notifyListeners();
  }

  void setSelectedIndex(int index) {
    if (index >= 0 && index < _results.length) {
      _selectedIndex = index;
      notifyListeners();
    }
  }

  void resetToDefaults() {
    _echConfigList = EchService.defaultEchConfigList;
    _socksPort = 10808;
    _httpPort = 10809;
    _dnsServer = EchService.defaultDnsServer;
    _domesticDns = EchService.defaultDomesticDns;
    _remarkSuffix = '-ech';
    _fingerprint = 'chrome';
    _alpnText = 'http/1.1';
    _allowInsecure = false;
    notifyListeners();
  }

  void clear() {
    _inputText = '';
    _results = [];
    _selectedIndex = 0;
    _errorMessage = null;
    _isProcessing = false;
    notifyListeners();
  }

  List<String> _parseAlpnList(String text) {
    return text
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
  }

  void transform() {
    final trimmed = _inputText.trim();
    if (trimmed.isEmpty) {
      _errorMessage = 'Please enter or paste a proxy link (VLESS, VMess, Trojan, SS) or Xray JSON config.';
      _results = [];
      notifyListeners();
      return;
    }

    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final alpnList = _parseAlpnList(_alpnText);

      // Check if input is a JSON object/array
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        final res = EchService.addEchToInput(
          trimmed,
          echConfigList: _echConfigList,
          socksPort: _socksPort,
          httpPort: _httpPort,
          dnsServer: _dnsServer,
          domesticDns: _domesticDns,
          remarkSuffix: _remarkSuffix,
          fingerprint: _fingerprint,
          alpn: alpnList,
          allowInsecure: _allowInsecure,
        );
        _results = [res];
        _selectedIndex = 0;
        _errorMessage = null;
      } else {
        // Multi-line or single URI links
        final lines = trimmed
            .split('\n')
            .map((l) => l.trim())
            .where((l) => l.isNotEmpty && !l.startsWith('//') && !l.startsWith('#'))
            .toList();

        if (lines.isEmpty) {
          throw const FormatException('No valid lines found in input.');
        }

        final transformed = <EchResult>[];
        for (int i = 0; i < lines.length; i++) {
          try {
            final res = EchService.addEchToInput(
              lines[i],
              echConfigList: _echConfigList,
              socksPort: _socksPort,
              httpPort: _httpPort,
              dnsServer: _dnsServer,
              domesticDns: _domesticDns,
              remarkSuffix: _remarkSuffix,
              fingerprint: _fingerprint,
              alpn: alpnList,
              allowInsecure: _allowInsecure,
            );
            transformed.add(res);
          } catch (e) {
            if (lines.length == 1) rethrow;
          }
        }

        if (transformed.isEmpty) {
          throw const FormatException('Failed to transform any of the provided links.');
        }

        _results = transformed;
        _selectedIndex = 0;
        _errorMessage = null;
      }
    } catch (e) {
      _errorMessage = e.toString().replaceAll('FormatException: ', '');
      _results = [];
    } finally {
      _isProcessing = false;
      notifyListeners();
    }
  }
}
