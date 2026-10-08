import 'dart:convert';
import 'proxy_parser_service.dart';

/// Represents a proxy outbound extracted from a share link or Xray config,
/// with an associated label.
class _ExtractedProxy {
  final Map<String, dynamic> outbound;
  final String label;

  _ExtractedProxy({
    required this.outbound,
    required this.label,
  });
}

/// Service to generate Xray LeastPing Balancer JSON configurations from
/// multiple individual proxy configs or share links (VLESS, VMess, Trojan, SS, SOCKS, HTTP).
class LoadBalancerService {
  static const Set<String> nonProxyProtocols = {
    'freedom',
    'blackhole',
    'dns',
  };

  static const Set<String> nonProxyTags = {
    'direct',
    'block',
    'dns-out',
  };

  /// Sanitize remarks or names to create a clean tag suffix.
  static String sanitizeTag(String name) {
    var sanitized = name.trim().replaceAll(RegExp(r'[^a-zA-Z0-9_-]'), '_');
    sanitized = sanitized.replaceAll(RegExp(r'^_+|_+$'), '');
    return sanitized;
  }

  /// Extracts proxy outbounds from an Xray config.
  /// Identifies outbounds that are not direct / blackhole / dns built-ins.
  static List<Map<String, dynamic>> extractProxyOutbounds(Map<String, dynamic> config) {
    final outbounds = config['outbounds'];
    if (outbounds is! List) return [];

    final proxyOutbounds = <Map<String, dynamic>>[];
    for (final ob in outbounds) {
      if (ob is! Map) continue;
      final protocol = ob['protocol']?.toString().toLowerCase() ?? '';
      final tag = ob['tag']?.toString().toLowerCase() ?? '';

      if (nonProxyProtocols.contains(protocol) || nonProxyTags.contains(tag)) {
        continue;
      }

      proxyOutbounds.add(json.decode(json.encode(ob)) as Map<String, dynamic>);
    }
    return proxyOutbounds;
  }

  /// Merges DNS settings (hosts and servers) from multiple configs.
  static Map<String, dynamic> mergeDns(List<Map<String, dynamic>> configs) {
    final mergedHosts = <String, dynamic>{};
    final mergedServers = <String>[];

    for (final cfg in configs) {
      final dns = cfg['dns'];
      if (dns is Map) {
        final hosts = dns['hosts'];
        if (hosts is Map) {
          for (final entry in hosts.entries) {
            final domain = entry.key.toString();
            final ipVal = entry.value;

            if (!mergedHosts.containsKey(domain)) {
              if (ipVal is List) {
                mergedHosts[domain] = List<dynamic>.from(ipVal);
              } else {
                mergedHosts[domain] = ipVal;
              }
            } else {
              final curr = mergedHosts[domain];
              if (curr is List && ipVal is List) {
                for (final ip in ipVal) {
                  if (!curr.contains(ip)) {
                    curr.add(ip);
                  }
                }
              } else if (curr is List && ipVal is String) {
                if (!curr.contains(ipVal)) {
                  curr.add(ipVal);
                }
              } else if (curr is String && ipVal is List) {
                final mergedList = <dynamic>[curr];
                for (final ip in ipVal) {
                  if (!mergedList.contains(ip)) {
                    mergedList.add(ip);
                  }
                }
                mergedHosts[domain] = mergedList;
              } else if (curr is String && ipVal is String) {
                if (curr != ipVal) {
                  mergedHosts[domain] = <dynamic>[curr, ipVal];
                }
              }
            }
          }
        }

        final servers = dns['servers'];
        if (servers is List) {
          for (final s in servers) {
            final sStr = s.toString();
            if (!mergedServers.contains(sStr)) {
              mergedServers.add(sStr);
            }
          }
        }
      }
    }

    if (mergedServers.isEmpty) {
      mergedServers.add('1.1.1.1');
    }

    return {
      'hosts': mergedHosts,
      'servers': mergedServers,
      'tag': 'dns-module',
    };
  }

  /// Merges inbounds from multiple configs, preserving distinct ports/protocols.
  static List<Map<String, dynamic>> mergeInbounds(
    List<Map<String, dynamic>> configs, {
    int? socksPort,
    int? httpPort,
  }) {
    final merged = <Map<String, dynamic>>[];
    final seenPorts = <int>{};

    for (final cfg in configs) {
      final inbounds = cfg['inbounds'];
      if (inbounds is List) {
        for (final ib in inbounds) {
          if (ib is! Map) continue;
          final ibCopy = json.decode(json.encode(ib)) as Map<String, dynamic>;
          final proto = ibCopy['protocol']?.toString().toLowerCase() ?? '';

          if (socksPort != null && proto == 'socks') {
            ibCopy['port'] = socksPort;
          } else if (httpPort != null && proto == 'http') {
            ibCopy['port'] = httpPort;
          }

          final port = ibCopy['port'];
          final portNum = port is int ? port : (int.tryParse(port?.toString() ?? ''));

          if (portNum != null && seenPorts.contains(portNum)) {
            // If an inbound enables UDP, ensure it stays enabled
            if (proto == 'socks' &&
                ibCopy['settings'] is Map &&
                ibCopy['settings']['udp'] == true) {
              for (final m in merged) {
                if (m['port'] == portNum &&
                    m['protocol']?.toString().toLowerCase() == 'socks') {
                  if (m['settings'] is Map) {
                    m['settings']['udp'] = true;
                  } else {
                    m['settings'] = {'udp': true};
                  }
                }
              }
            }
            continue;
          }

          if (portNum != null) {
            seenPorts.add(portNum);
          }
          merged.add(ibCopy);
        }
      }
    }

    if (merged.isEmpty) {
      merged.add({
        'listen': '127.0.0.1',
        'port': socksPort ?? 10808,
        'protocol': 'socks',
        'settings': {
          'auth': 'noauth',
          'udp': true,
          'userLevel': 8,
        },
        'sniffing': {
          'destOverride': ['http', 'tls', 'quic'],
          'enabled': true,
          'routeOnly': false,
        },
        'tag': 'socks',
      });
    }

    if (httpPort != null && !seenPorts.contains(httpPort)) {
      merged.add({
        'listen': '127.0.0.1',
        'port': httpPort,
        'protocol': 'http',
        'settings': {},
        'tag': 'http',
      });
    }

    return merged;
  }

  /// Expands raw input strings, handling multi-line pasted links or single configs.
  static List<String> expandRawInputs(List<String> rawInputs) {
    final expanded = <String>[];
    for (final raw in rawInputs) {
      final trimmed = raw.trim();
      if (trimmed.isEmpty) continue;

      // Check if it's JSON
      if (trimmed.startsWith('{') ||
          trimmed.startsWith('[') ||
          trimmed.startsWith('//') ||
          trimmed.startsWith('/*')) {
        expanded.add(trimmed);
        continue;
      }

      // Check if it has multiple lines of URIs
      final lines = trimmed.split('\n').map((l) => l.trim()).where((l) => l.isNotEmpty).toList();
      if (lines.length > 1 && lines.any((l) => l.contains('://'))) {
        expanded.addAll(lines);
      } else {
        expanded.add(trimmed);
      }
    }
    return expanded;
  }

  /// Generates a complete Xray LeastPing Balancer JSON configuration map.
  static Map<String, dynamic> generateBalancerProfile({
    required List<String> inputs,
    String probeUrl = 'https://www.google.com/generate_204',
    String probeInterval = '3m',
    bool enableConcurrency = true,
    String strategyType = 'leastPing',
    String remarks = 'leastping',
    int? socksPort = 10808,
    int? httpPort,
  }) {
    final validInputs = expandRawInputs(inputs);

    if (validInputs.isEmpty) {
      throw const FormatException('At least one configuration or proxy link must be provided.');
    }

    final parsedConfigs = <Map<String, dynamic>>[];
    final extractedProxies = <_ExtractedProxy>[];

    for (int i = 0; i < validInputs.length; i++) {
      final input = validInputs[i];
      try {
        // Attempt JSON parse first if it looks like JSON
        if (input.startsWith('{') ||
            input.startsWith('[') ||
            input.startsWith('//') ||
            input.startsWith('/*')) {
          final sanitized = ProxyParserService.sanitizeJson(input);
          final decoded = json.decode(sanitized);

          if (decoded is Map<String, dynamic>) {
            final baseLabel = decoded['remarks']?.toString() ?? 'node_${i + 1}';

            if (decoded.containsKey('outbounds') && decoded['outbounds'] is List) {
              // Full Xray configuration
              parsedConfigs.add(decoded);
              final proxies = extractProxyOutbounds(decoded);
              for (final ob in proxies) {
                final tag = ob['tag']?.toString();
                final label = (tag != null && tag.isNotEmpty && tag != 'proxy')
                    ? tag
                    : baseLabel;
                extractedProxies.add(_ExtractedProxy(outbound: ob, label: label));
              }
            } else if (decoded.containsKey('protocol')) {
              // Standalone outbound JSON
              final proto = decoded['protocol'].toString().toLowerCase();
              if (!nonProxyProtocols.contains(proto)) {
                final tag = decoded['tag']?.toString();
                final label = (tag != null && tag.isNotEmpty) ? tag : baseLabel;
                extractedProxies.add(_ExtractedProxy(outbound: decoded, label: label));
              }
            } else {
              throw const FormatException('JSON does not contain outbounds or a proxy protocol.');
            }
          } else if (decoded is List) {
            for (int j = 0; j < decoded.length; j++) {
              final item = decoded[j];
              if (item is Map) {
                final itemMap = Map<String, dynamic>.from(item);
                final proto = itemMap['protocol']?.toString().toLowerCase();
                if (proto != null && !nonProxyProtocols.contains(proto)) {
                  final label = itemMap['tag']?.toString() ?? 'node_${i + 1}_$j';
                  extractedProxies.add(_ExtractedProxy(outbound: itemMap, label: label));
                }
              }
            }
          }
        } else {
          // Parse share link (VLESS, VMess, Trojan, SS, SOCKS, HTTP)
          final parsedNode = ProxyParserService.parseLink(input);
          final outbound = parsedNode.toXrayOutbound(tag: 'temp');
          final label = parsedNode.remarks.isNotEmpty ? parsedNode.remarks : 'node_${i + 1}';
          extractedProxies.add(_ExtractedProxy(outbound: outbound, label: label));
        }
      } catch (e) {
        throw FormatException('Failed to parse input #${i + 1}: $e');
      }
    }

    if (extractedProxies.isEmpty) {
      throw const FormatException(
        'No valid proxy outbounds found in the provided inputs. Please provide valid proxy links or Xray JSON configs.',
      );
    }

    final baseConfig = parsedConfigs.isNotEmpty ? parsedConfigs.first : <String, dynamic>{};

    // 1. DNS Merging
    final dnsSection = mergeDns(parsedConfigs);

    // 2. Inbounds Configuration
    final inbounds = mergeInbounds(parsedConfigs, socksPort: socksPort, httpPort: httpPort);

    // 3. Extract & Tag Proxy Outbounds
    const subjectPrefix = 'proxy-proxy-';
    final proxyOutbounds = <Map<String, dynamic>>[];
    int outboundCounter = 1;

    for (final ep in extractedProxies) {
      final obCopy = json.decode(json.encode(ep.outbound)) as Map<String, dynamic>;
      final cleanLabel = sanitizeTag(ep.label);
      if (cleanLabel.isNotEmpty) {
        obCopy['tag'] = '$subjectPrefix$outboundCounter-$cleanLabel';
      } else {
        obCopy['tag'] = '$subjectPrefix$outboundCounter';
      }
      proxyOutbounds.add(obCopy);
      outboundCounter++;
    }

    // Standard fallback outbounds
    final directOutbound = <String, dynamic>{
      'protocol': 'freedom',
      'streamSettings': {
        'network': 'tcp',
        'sockopt': {
          'domainStrategy': 'UseIP',
        },
      },
      'tag': 'direct',
    };

    final blockOutbound = <String, dynamic>{
      'protocol': 'blackhole',
      'settings': <String, dynamic>{},
      'tag': 'block',
    };

    final allOutbounds = [...proxyOutbounds, directOutbound, blockOutbound];

    // 4. Observatory Configuration
    final observatory = <String, dynamic>{
      'enableConcurrency': enableConcurrency,
      'probeInterval': probeInterval,
      'probeUrl': probeUrl,
      'subjectSelector': [subjectPrefix],
    };

    // 5. Routing Balancers & Rules
    const balancerTag = 'balancer-main';
    final routing = <String, dynamic>{
      'balancers': [
        {
          'selector': [subjectPrefix],
          'strategy': {
            'type': strategyType,
          },
          'tag': balancerTag,
        },
      ],
      'domainStrategy': baseConfig['routing'] is Map
          ? (baseConfig['routing']['domainStrategy'] ?? 'AsIs')
          : 'AsIs',
      'rules': [
        {
          'balancerTag': balancerTag,
          'inboundTag': ['dns-module'],
          'type': 'field',
        },
        {
          'balancerTag': balancerTag,
          'network': 'tcp,udp',
          'type': 'field',
        },
      ],
    };

    // 6. Policy & Logging
    final policy = baseConfig['policy'] ?? {
      'levels': {
        '8': {
          'connIdle': 300,
          'downlinkOnly': 1,
          'handshake': 4,
          'uplinkOnly': 1,
        },
      },
      'system': {
        'statsOutboundUplink': true,
        'statsOutboundDownlink': true,
      },
    };

    final log = baseConfig['log'] ?? {
      'loglevel': 'warning',
    };

    final stats = baseConfig['stats'] ?? <String, dynamic>{};

    return {
      'dns': dnsSection,
      'inbounds': inbounds,
      'log': log,
      'observatory': observatory,
      'outbounds': allOutbounds,
      'policy': policy,
      'remarks': remarks,
      'routing': routing,
      'stats': stats,
    };
  }
}
