import 'package:flutter/foundation.dart';
import '../../../core/services/cloudflare_fix_service.dart';

class CloudflareFixController extends ChangeNotifier {
  String _inputText = '';
  String get inputText => _inputText;

  int _socksPort = 10808;
  int get socksPort => _socksPort;

  int _httpPort = 10809;
  int get httpPort => _httpPort;

  String _dnsServer = CloudflareFixService.defaultDnsServer;
  String get dnsServer => _dnsServer;

  String _remarkSuffix = '-custom';
  String get remarkSuffix => _remarkSuffix;

  List<CloudflareFixResult> _results = [];
  List<CloudflareFixResult> get results => _results;

  String? _errorMessage;
  String? get errorMessage => _errorMessage;

  bool _isProcessing = false;
  bool get isProcessing => _isProcessing;

  void setInputText(String value) {
    _inputText = value;
    _errorMessage = null;
    notifyListeners();
  }

  void setSocksPort(int value) {
    _socksPort = value;
    notifyListeners();
  }

  void setHttpPort(int value) {
    _httpPort = value;
    notifyListeners();
  }

  void setDnsServer(String value) {
    _dnsServer = value;
    notifyListeners();
  }

  void setRemarkSuffix(String value) {
    _remarkSuffix = value;
    notifyListeners();
  }

  void transform() {
    final trimmed = _inputText.trim();
    if (trimmed.isEmpty) {
      _errorMessage = 'Please enter or paste a VLESS link.';
      _results = [];
      notifyListeners();
      return;
    }

    _isProcessing = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final lines = trimmed
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty)
          .toList();

      final newResults = <CloudflareFixResult>[];

      for (final link in lines) {
        final res = CloudflareFixService.transformVlessUrl(
          link,
          socksPort: _socksPort,
          httpPort: _httpPort,
          dnsServer: _dnsServer.isNotEmpty
              ? _dnsServer
              : CloudflareFixService.defaultDnsServer,
          remarkSuffix: _remarkSuffix,
        );
        newResults.add(res);
      }

      _results = newResults;
      _errorMessage = null;
    } catch (e) {
      _errorMessage = e is FormatException ? e.message : e.toString();
      _results = [];
    } finally {
      _isProcessing = false;
      notifyListeners();
    }
  }

  void clear() {
    _inputText = '';
    _results = [];
    _errorMessage = null;
    notifyListeners();
  }
}
