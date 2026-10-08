import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../../core/services/load_balancer_service.dart';

class LoadBalancerController extends ChangeNotifier {
  // Input configs or share links (at least 2 slots by default)
  List<String> _inputConfigs = ['', ''];
  int _socksPort = 10808;
  int? _httpPort = 10809;
  String _probeUrl = 'https://www.google.com/generate_204';
  String _probeInterval = '3m';
  String _strategyType = 'leastPing';
  bool _enableConcurrency = true;
  String _remarks = 'leastping';

  String? _generatedJson;
  String? _errorMessage;
  bool _isGenerating = false;

  List<String> get inputConfigs => List.unmodifiable(_inputConfigs);
  int get socksPort => _socksPort;
  int? get httpPort => _httpPort;
  String get probeUrl => _probeUrl;
  String get probeInterval => _probeInterval;
  String get strategyType => _strategyType;
  bool get enableConcurrency => _enableConcurrency;
  String get remarks => _remarks;
  String? get generatedJson => _generatedJson;
  String? get errorMessage => _errorMessage;
  bool get isGenerating => _isGenerating;

  /// Update input at index
  void setInputConfig(int index, String value) {
    if (index >= 0 && index < _inputConfigs.length) {
      _inputConfigs[index] = value.trim();
      _errorMessage = null;
      notifyListeners();
    }
  }

  /// Add a new input slot
  void addInputConfig([String value = '']) {
    _inputConfigs.add(value.trim());
    _errorMessage = null;
    notifyListeners();
  }

  /// Remove an input slot
  void removeInputConfig(int index) {
    if (_inputConfigs.length > 1 && index >= 0 && index < _inputConfigs.length) {
      _inputConfigs.removeAt(index);
      _errorMessage = null;
      notifyListeners();
    }
  }

  /// Add multiple inputs from bulk paste
  void addBulkInputs(String rawText) {
    final lines = LoadBalancerService.expandRawInputs([rawText]);
    if (lines.isEmpty) return;

    // Check if current inputs are all empty
    final allEmpty = _inputConfigs.every((e) => e.trim().isEmpty);
    if (allEmpty) {
      _inputConfigs = List<String>.from(lines);
    } else {
      // Clean trailing empty entries and append
      _inputConfigs.removeWhere((e) => e.trim().isEmpty);
      _inputConfigs.addAll(lines);
    }

    if (_inputConfigs.length < 2) {
      _inputConfigs.add('');
    }

    _errorMessage = null;
    notifyListeners();
  }

  void setSocksPort(int port) {
    _socksPort = port;
    notifyListeners();
  }

  void setHttpPort(int? port) {
    _httpPort = port;
    notifyListeners();
  }

  void setProbeUrl(String url) {
    _probeUrl = url.trim();
    notifyListeners();
  }

  void setProbeInterval(String interval) {
    _probeInterval = interval.trim();
    notifyListeners();
  }

  void setStrategyType(String strategy) {
    _strategyType = strategy;
    notifyListeners();
  }

  void setEnableConcurrency(bool enable) {
    _enableConcurrency = enable;
    notifyListeners();
  }

  void setRemarks(String remarks) {
    _remarks = remarks.trim();
    notifyListeners();
  }

  void clear() {
    _inputConfigs = ['', ''];
    _generatedJson = null;
    _errorMessage = null;
    _isGenerating = false;
    notifyListeners();
  }

  Future<void> generateBalancer() async {
    final validInputs = _inputConfigs.map((e) => e.trim()).where((e) => e.isNotEmpty).toList();

    if (validInputs.isEmpty) {
      _errorMessage = 'Please provide at least 1 valid proxy link or Xray JSON config.';
      _generatedJson = null;
      notifyListeners();
      return;
    }

    _isGenerating = true;
    _errorMessage = null;
    notifyListeners();

    try {
      final profile = LoadBalancerService.generateBalancerProfile(
        inputs: validInputs,
        probeUrl: _probeUrl.isNotEmpty ? _probeUrl : 'https://www.google.com/generate_204',
        probeInterval: _probeInterval.isNotEmpty ? _probeInterval : '3m',
        enableConcurrency: _enableConcurrency,
        strategyType: _strategyType,
        remarks: _remarks.isNotEmpty ? _remarks : 'leastping',
        socksPort: _socksPort,
        httpPort: _httpPort,
      );

      const encoder = JsonEncoder.withIndent('  ');
      _generatedJson = encoder.convert(profile);
      _errorMessage = null;
    } catch (e) {
      _errorMessage = e.toString().replaceAll('FormatException: ', '');
      _generatedJson = null;
    } finally {
      _isGenerating = false;
      notifyListeners();
    }
  }
}
