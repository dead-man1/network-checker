import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:provider/provider.dart';

import 'cloudflare_fix_controller.dart';

class CloudflareFixScreen extends StatefulWidget {
  const CloudflareFixScreen({super.key});

  @override
  State<CloudflareFixScreen> createState() => _CloudflareFixScreenState();
}

class _CloudflareFixScreenState extends State<CloudflareFixScreen> {
  late TextEditingController _textController;
  late TextEditingController _socksPortController;
  late TextEditingController _httpPortController;
  late TextEditingController _dnsServerController;
  late TextEditingController _remarkSuffixController;
  bool _showSettings = false;

  static const String _exampleVlessUrl =
      'vless://00000000-0000-0000-0000-000000000000@example.com:443?path=%2Fpath&security=tls&alpn=h3%2Ch2%2Chttp%2F1.1&encryption=none&host=example.com&fp=chrome&type=ws&sni=example.com#CloudflareFixExample';

  @override
  void initState() {
    super.initState();
    final controller = context.read<CloudflareFixController>();
    _textController = TextEditingController(text: controller.inputText);
    _socksPortController = TextEditingController(text: controller.socksPort.toString());
    _httpPortController = TextEditingController(text: controller.httpPort.toString());
    _dnsServerController = TextEditingController(text: controller.dnsServer);
    _remarkSuffixController = TextEditingController(text: controller.remarkSuffix);
  }

  @override
  void dispose() {
    _textController.dispose();
    _socksPortController.dispose();
    _httpPortController.dispose();
    _dnsServerController.dispose();
    _remarkSuffixController.dispose();
    super.dispose();
  }

  void _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null && data!.text!.isNotEmpty) {
      _textController.text = data.text!;
      if (mounted) {
        context.read<CloudflareFixController>().setInputText(data.text!);
      }
    }
  }

  void _loadExample() {
    _textController.text = _exampleVlessUrl;
    context.read<CloudflareFixController>().setInputText(_exampleVlessUrl);
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied to clipboard'),
        duration: const Duration(seconds: 2),
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final controller = context.watch<CloudflareFixController>();

    return Scaffold(
      appBar: AppBar(
        title: const Row(
          children: [
            Icon(Icons.auto_fix_high_rounded, color: Colors.amber),
            SizedBox(width: 10),
            Text('Patt\'s Cloudflare Fix'),
          ],
        ),
        actions: [
          IconButton(
            icon: Icon(_showSettings ? Icons.tune : Icons.tune_outlined),
            tooltip: 'Toggle Settings',
            onPressed: () => setState(() => _showSettings = !_showSettings),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 900),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // Info Banner highlighting supported formats
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: colorScheme.primaryContainer.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: colorScheme.primary.withValues(alpha: 0.3),
                    ),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.info_outline_rounded, color: colorScheme.primary),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          'Supports VLESS+TLS+WS and VLESS+TLS+xHTTP links only. It transforms configurations into Cloudflare-optimized Xray JSON.',
                          style: TextStyle(
                            fontSize: 13.5,
                            fontWeight: FontWeight.w500,
                            color: colorScheme.onSurface,
                          ),
                        ),
                      ),
                    ],
                  ),
                ).animate().fadeIn(duration: 300.ms),

                const SizedBox(height: 16),

                // Settings Panel (Collapsible)
                if (_showSettings)
                  Card(
                    elevation: 0,
                    color: colorScheme.surfaceContainerHigh.withValues(alpha: 0.6),
                    margin: const EdgeInsets.only(bottom: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                      side: BorderSide(
                        color: colorScheme.outlineVariant.withValues(alpha: 0.5),
                      ),
                    ),
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Configuration Options',
                            style: TextStyle(
                              fontSize: 15,
                              fontWeight: FontWeight.bold,
                              color: colorScheme.primary,
                            ),
                          ),
                          const SizedBox(height: 12),
                          Row(
                            children: [
                              Expanded(
                                child: TextField(
                                  controller: _socksPortController,
                                  keyboardType: TextInputType.number,
                                  decoration: const InputDecoration(
                                    labelText: 'SOCKS Inbound Port',
                                    isDense: true,
                                    border: OutlineInputBorder(),
                                  ),
                                  onChanged: (v) {
                                    final p = int.tryParse(v);
                                    if (p != null) controller.setSocksPort(p);
                                  },
                                ),
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: TextField(
                                  controller: _httpPortController,
                                  keyboardType: TextInputType.number,
                                  decoration: const InputDecoration(
                                    labelText: 'HTTP Inbound Port',
                                    isDense: true,
                                    border: OutlineInputBorder(),
                                  ),
                                  onChanged: (v) {
                                    final p = int.tryParse(v);
                                    if (p != null) controller.setHttpPort(p);
                                  },
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _dnsServerController,
                            decoration: const InputDecoration(
                              labelText: 'DNS DoH Server URL',
                              isDense: true,
                              border: OutlineInputBorder(),
                            ),
                            onChanged: (v) => controller.setDnsServer(v),
                          ),
                          const SizedBox(height: 12),
                          TextField(
                            controller: _remarkSuffixController,
                            decoration: const InputDecoration(
                              labelText: 'Remark Suffix',
                              isDense: true,
                              border: OutlineInputBorder(),
                            ),
                            onChanged: (v) => controller.setRemarkSuffix(v),
                          ),
                        ],
                      ),
                    ),
                  ).animate().fadeIn(duration: 250.ms),

                // Main Input Card
                Card(
                  elevation: 0,
                  color: colorScheme.surfaceContainerLow,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(18),
                    side: BorderSide(
                      color: colorScheme.outlineVariant.withValues(alpha: 0.6),
                    ),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              'VLESS Share Link',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.bold,
                                color: colorScheme.onSurface,
                              ),
                            ),
                            Wrap(
                              spacing: 6,
                              children: [
                                TextButton.icon(
                                  onPressed: _pasteFromClipboard,
                                  icon: const Icon(Icons.content_paste_rounded, size: 16),
                                  label: const Text('Paste'),
                                ),
                                TextButton.icon(
                                  onPressed: _loadExample,
                                  icon: const Icon(Icons.lightbulb_outline_rounded, size: 16),
                                  label: const Text('Example'),
                                ),
                                if (controller.inputText.isNotEmpty)
                                  IconButton(
                                    icon: const Icon(Icons.clear_rounded, size: 18),
                                    onPressed: () {
                                      _textController.clear();
                                      controller.clear();
                                    },
                                    tooltip: 'Clear input',
                                  ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 10),
                        TextField(
                          controller: _textController,
                          maxLines: 4,
                          minLines: 2,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 13,
                          ),
                          decoration: InputDecoration(
                            hintText: 'Paste vless://... (VLESS+TLS+WS or VLESS+TLS+xHTTP)',
                            hintStyle: TextStyle(
                              color: colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
                            ),
                            border: OutlineInputBorder(
                              borderRadius: BorderRadius.circular(12),
                            ),
                            contentPadding: const EdgeInsets.all(14),
                          ),
                          onChanged: (val) => controller.setInputText(val),
                        ),
                        const SizedBox(height: 16),
                        FilledButton.icon(
                          onPressed: controller.isProcessing
                              ? null
                              : () => controller.transform(),
                          icon: const Icon(Icons.auto_fix_high_rounded),
                          label: Padding(
                            padding: const EdgeInsets.symmetric(vertical: 12),
                            child: Text(
                              controller.isProcessing
                                  ? 'Transforming...'
                                  : 'Transform to Cloudflare Fix JSON',
                              style: const TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ).animate().fadeIn(duration: 350.ms),

                const SizedBox(height: 16),

                // Error Banner
                if (controller.errorMessage != null)
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: colorScheme.errorContainer,
                      borderRadius: BorderRadius.circular(14),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.warning_amber_rounded, color: colorScheme.onErrorContainer),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            controller.errorMessage!,
                            style: TextStyle(
                              color: colorScheme.onErrorContainer,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ).animate().shake(duration: 300.ms),

                // Results View
                if (controller.results.isNotEmpty) ...[
                  ...controller.results.map((res) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        // Summary info card
                        Card(
                          elevation: 0,
                          color: colorScheme.primaryContainer.withValues(alpha: 0.3),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                            side: BorderSide(
                              color: colorScheme.primary.withValues(alpha: 0.3),
                            ),
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(14),
                            child: Wrap(
                              spacing: 16,
                              runSpacing: 8,
                              children: [
                                _buildSummaryChip(
                                  context,
                                  Icons.label_outlined,
                                  'Remarks',
                                  res.remarks,
                                ),
                                _buildSummaryChip(
                                  context,
                                  Icons.dns_outlined,
                                  'Server',
                                  '${res.address}:${res.port}',
                                ),
                                _buildSummaryChip(
                                  context,
                                  Icons.wifi_tethering_rounded,
                                  'Transport',
                                  res.network,
                                ),
                                _buildSummaryChip(
                                  context,
                                  Icons.lock_outline_rounded,
                                  'SNI',
                                  res.sni,
                                ),
                                _buildSummaryChip(
                                  context,
                                  Icons.shield_outlined,
                                  'Fingerprint',
                                  'unsafe',
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 12),
                        // JSON Code output box
                        Card(
                          elevation: 0,
                          color: colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                            side: BorderSide(
                              color: colorScheme.outlineVariant,
                            ),
                          ),
                          child: Padding(
                            padding: const EdgeInsets.all(14),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                Row(
                                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                  children: [
                                    Text(
                                      'Xray Config JSON',
                                      style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.bold,
                                        color: colorScheme.primary,
                                      ),
                                    ),
                                    FilledButton.icon(
                                      onPressed: () => _copyToClipboard(
                                        res.formattedJson,
                                        'Cloudflare Fix JSON',
                                      ),
                                      icon: const Icon(Icons.copy_rounded, size: 16),
                                      label: const Text('Copy JSON'),
                                      style: FilledButton.styleFrom(
                                        visualDensity: VisualDensity.compact,
                                      ),
                                    ),
                                  ],
                                ),
                                const SizedBox(height: 10),
                                Container(
                                  padding: const EdgeInsets.all(12),
                                  decoration: BoxDecoration(
                                    color: colorScheme.surface,
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                  child: SelectableText(
                                    res.formattedJson,
                                    style: const TextStyle(
                                      fontFamily: 'monospace',
                                      fontSize: 12,
                                      height: 1.4,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(height: 16),
                      ],
                    );
                  }),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSummaryChip(
    BuildContext context,
    IconData icon,
    String label,
    String value,
  ) {
    final colorScheme = Theme.of(context).colorScheme;
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, size: 16, color: colorScheme.primary),
        const SizedBox(width: 6),
        Text(
          '$label: ',
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.bold,
            color: colorScheme.onSurfaceVariant,
          ),
        ),
        Text(
          value,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: colorScheme.onSurface,
          ),
        ),
      ],
    );
  }
}
