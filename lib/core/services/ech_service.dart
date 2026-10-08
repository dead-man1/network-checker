import 'dart:convert';
import 'proxy_parser_service.dart';
import 'cloudflare_fix_service.dart';

/// Result of an ECH transformation operation
class EchResult {
  final Map<String, dynamic> jsonConfig;
  final String formattedJson;
  final String remarks;
  final String protocol;
  final String address;
  final int port;
  final String network;
  final String sni;
  final String echConfigList;
  final String fingerprint;
  final List<String> alpn;
  final int proxyCount;

  EchResult({
    required this.jsonConfig,
    required this.formattedJson,
    required this.remarks,
    required this.protocol,
    required this.address,
    required this.port,
    required this.network,
    required this.sni,
    required this.echConfigList,
    required this.fingerprint,
    required this.alpn,
    this.proxyCount = 1,
  });
}

/// Service to transform proxy share links (VLESS, VMess, Trojan, SS, SOCKS, HTTP)
/// or Xray JSON configs (including Load Balancers and Multi-Hop Chains) into
/// ECH-enabled (Encrypted Client Hello) Xray JSON configurations
/// with FakeDNS, domestic DNS fallback, and routing rules.
class EchService {
  static const String defaultEchConfigList = 'cloudflare-ech.com+udp://1.1.1.1';
  static const String defaultDnsServer = 'https://cloudflare-dns.com/dns-query';
  static const String defaultDomesticDns = '223.5.5.5';

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

  /// Standard hosts mapping required for Cloudflare DNS functionality
  static Map<String, dynamic> get defaultDnsHosts => CloudflareFixService.defaultDnsHosts;

  /// Checks if an outbound map is a proxy outbound.
  static bool isProxyOutbound(Map<String, dynamic> ob) {
    final proto = ob['protocol']?.toString().toLowerCase() ?? '';
    final tag = ob['tag']?.toString().toLowerCase() ?? '';
    if (proto.isEmpty || nonProxyProtocols.contains(proto) || nonProxyTags.contains(tag)) {
      return false;
    }
    return true;
  }

  /// Extracts the effective serverName (SNI) from an outbound map.
  static String extractServerName(Map<String, dynamic> outbound) {
    final streamSettings = outbound['streamSettings'] as Map?;
    final tlsSettings = streamSettings?['tlsSettings'] as Map?;
    final realitySettings = streamSettings?['realitySettings'] as Map?;
    final existingSni = tlsSettings?['serverName']?.toString() ??
        realitySettings?['serverName']?.toString();
    if (existingSni != null && existingSni.isNotEmpty) {
      return existingSni;
    }

    final wsSettings = streamSettings?['wsSettings'] as Map?;
    final wsHost = wsSettings?['headers']?['Host']?.toString() ??
        wsSettings?['headers']?['host']?.toString() ??
        wsSettings?['host']?.toString();
    if (wsHost != null && wsHost.isNotEmpty) {
      return wsHost;
    }

    final httpSettings = streamSettings?['httpSettings'] as Map?;
    final httpHost = (httpSettings?['host'] is List)
        ? (httpSettings!['host'] as List).firstOrNull?.toString()
        : httpSettings?['host']?.toString();
    if (httpHost != null && httpHost.isNotEmpty) {
      return httpHost;
    }

    final xhttpSettings = streamSettings?['xhttpSettings'] as Map?;
    final xhttpHost = xhttpSettings?['host']?.toString();
    if (xhttpHost != null && xhttpHost.isNotEmpty) {
      return xhttpHost;
    }

    // Settings server/vnext address
    final settings = outbound['settings'] as Map?;
    final vnext = settings?['vnext'] as List?;
    if (vnext != null && vnext.isNotEmpty && vnext.first is Map) {
      final addr = vnext.first['address']?.toString();
      if (addr != null && addr.isNotEmpty) return addr;
    }

    final servers = settings?['servers'] as List?;
    if (servers != null && servers.isNotEmpty && servers.first is Map) {
      final addr = servers.first['address']?.toString();
      if (addr != null && addr.isNotEmpty) return addr;
    }

    return '';
  }

  /// Injects ECH configuration into a single outbound map, preserving all other properties.
  static Map<String, dynamic> applyEchToOutbound(
    Map<String, dynamic> outbound, {
    required String echConfigList,
    String? fingerprint,
    List<String>? alpn,
    bool allowInsecure = false,
  }) {
    final obCopy = json.decode(json.encode(outbound)) as Map<String, dynamic>;

    final streamSettings = Map<String, dynamic>.from(
      obCopy['streamSettings'] as Map? ?? {},
    );
    streamSettings['security'] = 'tls';

    final existingTls = Map<String, dynamic>.from(
      streamSettings['tlsSettings'] as Map? ?? {},
    );

    final serverName = extractServerName(obCopy);
    final effectiveSni = existingTls['serverName']?.toString().isNotEmpty == true
        ? existingTls['serverName']!.toString()
        : serverName;

    final effectiveAlpn = (alpn != null && alpn.isNotEmpty)
        ? alpn
        : (existingTls['alpn'] is List && (existingTls['alpn'] as List).isNotEmpty
            ? List<String>.from(existingTls['alpn'] as List)
            : ['http/1.1']);

    final effectiveFp = (fingerprint != null && fingerprint.isNotEmpty)
        ? fingerprint
        : (existingTls['fingerprint']?.toString().isNotEmpty == true
            ? existingTls['fingerprint']!.toString()
            : 'chrome');

    final effectiveEch = echConfigList.trim().isNotEmpty
        ? echConfigList.trim()
        : defaultEchConfigList;

    existingTls['allowInsecure'] = allowInsecure;
    existingTls['alpn'] = effectiveAlpn;
    existingTls['echConfigList'] = effectiveEch;
    existingTls['fingerprint'] = effectiveFp;
    if (effectiveSni.isNotEmpty) {
      existingTls['serverName'] = effectiveSni;
    }

    streamSettings['tlsSettings'] = existingTls;
    obCopy['streamSettings'] = streamSettings;

    if (obCopy['mux'] == null) {
      obCopy['mux'] = {
        'concurrency': -1,
        'enabled': false,
      };
    }

    return obCopy;
  }

  /// Builds the complete DNS section required for ECH.
  static Map<String, dynamic> _buildEchDns({
    required String dnsServer,
    required String domesticDns,
    Map<String, dynamic>? existingDns,
  }) {
    final hosts = Map<String, dynamic>.from(defaultDnsHosts);
    if (existingDns?['hosts'] is Map) {
      final existingHosts = existingDns!['hosts'] as Map;
      for (final entry in existingHosts.entries) {
        hosts[entry.key.toString()] = entry.value;
      }
    }

    return {
      'hosts': hosts,
      'servers': [
        {
          'address': 'fakedns',
          'domains': [
            'geosite:cn',
            'domain:ir',
            'geosite:category-ir',
          ],
        },
        dnsServer,
        {
          'address': domesticDns,
          'domains': [
            'domain:ir',
            'geosite:category-ir',
          ],
          'finalQuery': true,
          'skipFallback': true,
          'tag': 'domestic-dns_0_0',
        },
      ],
      'tag': 'dns-module',
    };
  }

  /// Ensures sniffing destOverride includes 'fakedns' in inbounds.
  static List<Map<String, dynamic>> _enrichInboundsWithFakeDns(
    List<dynamic> inbounds, {
    int socksPort = 10808,
    int? httpPort,
  }) {
    final enriched = <Map<String, dynamic>>[];
    final seenPorts = <int>{};

    for (final item in inbounds) {
      if (item is! Map) continue;
      final ibCopy = json.decode(json.encode(item)) as Map<String, dynamic>;
      final port = ibCopy['port'];
      final portNum = port is int ? port : (int.tryParse(port?.toString() ?? ''));

      // Ensure sniffing with fakedns
      final sniffing = Map<String, dynamic>.from(ibCopy['sniffing'] as Map? ?? {});
      sniffing['enabled'] = true;
      sniffing['routeOnly'] = false;
      final destOverride = List<String>.from(sniffing['destOverride'] as List? ?? ['http', 'tls', 'quic']);
      if (!destOverride.contains('fakedns')) {
        destOverride.add('fakedns');
      }
      sniffing['destOverride'] = destOverride;
      ibCopy['sniffing'] = sniffing;

      if (portNum != null) seenPorts.add(portNum);
      enriched.add(ibCopy);
    }

    if (enriched.isEmpty) {
      enriched.add({
        'listen': '127.0.0.1',
        'port': socksPort,
        'protocol': 'socks',
        'settings': {
          'auth': 'noauth',
          'udp': true,
        },
        'sniffing': {
          'destOverride': ['http', 'tls', 'quic', 'fakedns'],
          'enabled': true,
          'routeOnly': false,
        },
        'tag': 'socks',
      });
      seenPorts.add(socksPort);
    }

    if (httpPort != null && !seenPorts.contains(httpPort)) {
      enriched.add({
        'listen': '127.0.0.1',
        'port': httpPort,
        'protocol': 'http',
        'settings': {
          'userLevel': 8,
        },
        'sniffing': {
          'destOverride': ['http', 'tls', 'quic', 'fakedns'],
          'enabled': true,
          'routeOnly': false,
        },
        'tag': 'http',
      });
    }

    return enriched;
  }

  /// Transforms a single proxy link or full Xray JSON config into an ECH-optimized Xray JSON configuration.
  /// If given a Load Balancer or Chain JSON, it applies ECH to EACH proxy node while preserving the structure.
  static EchResult addEchToInput(
    String rawInput, {
    String echConfigList = defaultEchConfigList,
    int socksPort = 10808,
    int? httpPort,
    String dnsServer = defaultDnsServer,
    String domesticDns = defaultDomesticDns,
    String remarkSuffix = '-ech',
    String fingerprint = 'chrome',
    List<String> alpn = const ['http/1.1'],
    bool allowInsecure = false,
  }) {
    final trimmed = rawInput.trim();
    if (trimmed.isEmpty) {
      throw const FormatException('Input configuration cannot be empty.');
    }

    // Check if input is a JSON object
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      final sanitized = ProxyParserService.sanitizeJson(trimmed);
      final decoded = json.decode(sanitized);

      if (decoded is Map<String, dynamic>) {
        if (decoded.containsKey('outbounds') && decoded['outbounds'] is List) {
          return _transformFullJsonConfig(
            decoded,
            echConfigList: echConfigList,
            socksPort: socksPort,
            httpPort: httpPort,
            dnsServer: dnsServer,
            domesticDns: domesticDns,
            remarkSuffix: remarkSuffix,
            fingerprint: fingerprint,
            alpn: alpn,
            allowInsecure: allowInsecure,
          );
        } else if (decoded.containsKey('protocol')) {
          // Standalone outbound JSON
          final appliedOutbound = applyEchToOutbound(
            decoded,
            echConfigList: echConfigList,
            fingerprint: fingerprint,
            alpn: alpn,
            allowInsecure: allowInsecure,
          );
          appliedOutbound['tag'] = 'proxy';
          return _wrapOutboundIntoEchProfile(
            appliedOutbound,
            remarks: decoded['tag']?.toString() ?? 'proxy',
            echConfigList: echConfigList,
            socksPort: socksPort,
            httpPort: httpPort,
            dnsServer: dnsServer,
            domesticDns: domesticDns,
            remarkSuffix: remarkSuffix,
            fingerprint: fingerprint,
            alpn: alpn,
          );
        }
      }
    }

    // Otherwise, treat as share link (VLESS, VMess, Trojan, SS, SOCKS, HTTP)
    final ParsedProxyNode parsedNode;
    try {
      parsedNode = ProxyParserService.parseLink(trimmed);
    } catch (e) {
      throw FormatException('Failed to parse proxy node: $e');
    }

    final rawOutbound = parsedNode.toXrayOutbound(tag: 'proxy');
    final appliedOutbound = applyEchToOutbound(
      rawOutbound,
      echConfigList: echConfigList,
      fingerprint: fingerprint,
      alpn: alpn,
      allowInsecure: allowInsecure,
    );

    return _wrapOutboundIntoEchProfile(
      appliedOutbound,
      remarks: parsedNode.remarks.isNotEmpty ? parsedNode.remarks : 'proxy',
      echConfigList: echConfigList,
      socksPort: socksPort,
      httpPort: httpPort,
      dnsServer: dnsServer,
      domesticDns: domesticDns,
      remarkSuffix: remarkSuffix,
      fingerprint: fingerprint,
      alpn: alpn,
    );
  }

  /// Transforms a full Xray JSON config (Load Balancer, Multi-Hop Chain, or custom profile)
  /// by applying ECH to EVERY proxy outbound inside it, preserving balancer/chain topologies.
  static EchResult _transformFullJsonConfig(
    Map<String, dynamic> rootJson, {
    required String echConfigList,
    required int socksPort,
    required int? httpPort,
    required String dnsServer,
    required String domesticDns,
    required String remarkSuffix,
    required String fingerprint,
    required List<String> alpn,
    required bool allowInsecure,
  }) {
    final rawOutbounds = rootJson['outbounds'] as List;
    final updatedOutbounds = <Map<String, dynamic>>[];
    final proxyOutbounds = <Map<String, dynamic>>[];

    // 1. Apply ECH to EACH individual proxy outbound
    for (final item in rawOutbounds) {
      if (item is! Map) continue;
      final obMap = Map<String, dynamic>.from(item);

      if (isProxyOutbound(obMap)) {
        final withEch = applyEchToOutbound(
          obMap,
          echConfigList: echConfigList,
          fingerprint: fingerprint,
          alpn: alpn,
          allowInsecure: allowInsecure,
        );
        updatedOutbounds.add(withEch);
        proxyOutbounds.add(withEch);
      } else {
        updatedOutbounds.add(obMap);
      }
    }

    if (proxyOutbounds.isEmpty) {
      throw const FormatException('No proxy outbounds found in the configuration.');
    }

    // Ensure direct, block, and dns-out outbounds exist
    final hasDirect = updatedOutbounds.any((ob) => ob['tag'] == 'direct');
    final hasBlock = updatedOutbounds.any((ob) => ob['tag'] == 'block');
    final hasDnsOut = updatedOutbounds.any((ob) => ob['tag'] == 'dns-out');

    if (!hasDirect) {
      updatedOutbounds.add({'protocol': 'freedom', 'tag': 'direct'});
    }
    if (!hasBlock) {
      updatedOutbounds.add({'protocol': 'blackhole', 'tag': 'block'});
    }
    if (!hasDnsOut) {
      updatedOutbounds.add({
        'protocol': 'dns',
        'settings': {'userLevel': 12},
        'tag': 'dns-out',
      });
    }

    // 2. Identify config type: Load Balancer, Chain, or Standard
    final routing = Map<String, dynamic>.from(rootJson['routing'] as Map? ?? {});
    final balancers = routing['balancers'] as List?;
    final isLoadBalancer = balancers != null && balancers.isNotEmpty;

    final isChain = proxyOutbounds.length > 1 &&
        (proxyOutbounds.any((ob) {
          final stream = ob['streamSettings'] as Map?;
          final sockopt = stream?['sockopt'] as Map?;
          return sockopt?.containsKey('dialerProxy') == true;
        }) || proxyOutbounds.first['tag']?.toString().startsWith('hop') == true);

    // 3. DNS Section
    final dnsSection = _buildEchDns(
      dnsServer: dnsServer,
      domesticDns: domesticDns,
      existingDns: rootJson['dns'] as Map<String, dynamic>?,
    );

    // 4. Inbounds Section with FakeDNS
    final inboundsSection = _enrichInboundsWithFakeDns(
      rootJson['inbounds'] as List? ?? [],
      socksPort: socksPort,
      httpPort: httpPort,
    );

    // 5. Routing Rules Section
    final domainStrategy = routing['domainStrategy'] ?? 'AsIs';
    final existingRules = List<dynamic>.from(routing['rules'] as List? ?? []);

    final updatedRules = <Map<String, dynamic>>[];

    // Mandatory rule: port 53 -> dns-out
    updatedRules.add({
      'inboundTag': [
        'socks',
        if (httpPort != null) 'http',
      ],
      'outboundTag': 'dns-out',
      'port': '53',
      'type': 'field',
    });

    // Mandatory rule: domestic-dns_0_0 -> direct
    updatedRules.add({
      'inboundTag': ['domestic-dns_0_0'],
      'outboundTag': 'direct',
      'type': 'field',
    });

    // Target for dns-module
    if (isLoadBalancer) {
      final balancerTag = balancers.first['tag']?.toString() ?? 'balancer-main';
      updatedRules.add({
        'balancerTag': balancerTag,
        'inboundTag': ['dns-module'],
        'type': 'field',
      });
      // Retain or add balancer tcp,udp rule
      updatedRules.add({
        'balancerTag': balancerTag,
        'network': 'tcp,udp',
        'type': 'field',
      });
    } else if (isChain) {
      final finalHopTag = proxyOutbounds.last['tag']?.toString() ?? 'hop${proxyOutbounds.length - 1}';
      updatedRules.add({
        'inboundTag': ['dns-module'],
        'outboundTag': finalHopTag,
        'type': 'field',
      });
      updatedRules.add({
        'outboundTag': finalHopTag,
        'port': '0-65535',
        'type': 'field',
      });
    } else {
      final primaryProxyTag = proxyOutbounds.first['tag']?.toString() ?? 'proxy';
      updatedRules.add({
        'inboundTag': ['dns-module'],
        'outboundTag': primaryProxyTag,
        'type': 'field',
      });
    }

    // Direct rules for domestic IR domains and IPs
    updatedRules.add({
      'domain': [
        'domain:ir',
        'geosite:category-ir',
      ],
      'outboundTag': 'direct',
      'type': 'field',
    });

    updatedRules.add({
      'ip': [
        'geoip:ir',
      ],
      'outboundTag': 'direct',
      'type': 'field',
    });

    // Preserve any custom user routing rules not conflicting with our base rules
    for (final r in existingRules) {
      if (r is Map) {
        final rMap = Map<String, dynamic>.from(r);
        final inTag = rMap['inboundTag'];
        final port = rMap['port'];
        if ((inTag is List && (inTag.contains('socks') || inTag.contains('dns-module')) && port == '53') ||
            (inTag is List && inTag.contains('domestic-dns_0_0'))) {
          continue; // Already covered by our ECH rules
        }
        if (!updatedRules.any((ur) => ur['balancerTag'] != null && ur['balancerTag'] == rMap['balancerTag'] && ur['network'] == rMap['network'])) {
          updatedRules.add(rMap);
        }
      }
    }

    routing['domainStrategy'] = domainStrategy;
    routing['rules'] = updatedRules;

    // 6. Remarks
    final rawRemarks = rootJson['remarks']?.toString() ?? 'ech-profile';
    final finalRemarks = rawRemarks.endsWith(remarkSuffix)
        ? rawRemarks
        : '$rawRemarks$remarkSuffix';

    // 7. Policy
    final policy = Map<String, dynamic>.from(rootJson['policy'] as Map? ?? {});
    final levels = Map<String, dynamic>.from(policy['levels'] as Map? ?? {});
    levels.putIfAbsent('0', () => {'downlinkOnly': 0, 'uplinkOnly': 0});
    levels.putIfAbsent('12', () => {'connIdle': 12, 'downlinkOnly': 0, 'uplinkOnly': 0});
    policy['levels'] = levels;

    // 8. Assemble result
    final resultJson = Map<String, dynamic>.from(rootJson);
    resultJson['dns'] = dnsSection;
    resultJson['fakedns'] = [
      {'ipPool': '198.18.0.0/15', 'poolSize': 10000}
    ];
    resultJson['inbounds'] = inboundsSection;
    resultJson['log'] = rootJson['log'] ?? {'loglevel': 'warning'};
    resultJson['outbounds'] = updatedOutbounds;
    resultJson['policy'] = policy;
    resultJson['remarks'] = finalRemarks;
    resultJson['routing'] = routing;

    const encoder = JsonEncoder.withIndent('  ');
    final formatted = encoder.convert(resultJson);

    final String displayProtocol;
    final String displayAddress;
    if (isLoadBalancer) {
      displayProtocol = 'Load Balancer (${proxyOutbounds.length} nodes)';
      displayAddress = 'Least-Ping Balancer';
    } else if (isChain) {
      displayProtocol = 'Chain (${proxyOutbounds.length} hops)';
      displayAddress = '${proxyOutbounds.first['tag']} → ${proxyOutbounds.last['tag']}';
    } else {
      displayProtocol = proxyOutbounds.first['protocol']?.toString().toUpperCase() ?? 'PROXY';
      displayAddress = extractServerName(proxyOutbounds.first);
    }

    return EchResult(
      jsonConfig: resultJson,
      formattedJson: formatted,
      remarks: finalRemarks,
      protocol: displayProtocol,
      address: displayAddress,
      port: socksPort,
      network: proxyOutbounds.first['streamSettings']?['network']?.toString().toUpperCase() ?? 'TCP',
      sni: extractServerName(proxyOutbounds.first),
      echConfigList: echConfigList,
      fingerprint: fingerprint,
      alpn: alpn,
      proxyCount: proxyOutbounds.length,
    );
  }

  /// Wraps a single proxy outbound into the standard complete ECH profile matching /tmp/echconfig.json.
  static EchResult _wrapOutboundIntoEchProfile(
    Map<String, dynamic> appliedOutbound, {
    required String remarks,
    required String echConfigList,
    required int socksPort,
    required int? httpPort,
    required String dnsServer,
    required String domesticDns,
    required String remarkSuffix,
    required String fingerprint,
    required List<String> alpn,
  }) {
    final rawRemarks = remarks.isNotEmpty ? remarks : 'proxy';
    final finalRemarks = rawRemarks.endsWith(remarkSuffix)
        ? rawRemarks
        : '$rawRemarks$remarkSuffix';

    final effectiveSni = extractServerName(appliedOutbound);

    final inbounds = <Map<String, dynamic>>[
      {
        'listen': '127.0.0.1',
        'port': socksPort,
        'protocol': 'socks',
        'settings': {
          'auth': 'noauth',
          'udp': true,
        },
        'sniffing': {
          'destOverride': [
            'http',
            'tls',
            'quic',
            'fakedns',
          ],
          'enabled': true,
          'routeOnly': false,
        },
        'tag': 'socks',
      },
      if (httpPort != null)
        {
          'listen': '127.0.0.1',
          'port': httpPort,
          'protocol': 'http',
          'settings': {
            'userLevel': 8,
          },
          'sniffing': {
            'destOverride': [
              'http',
              'tls',
              'quic',
              'fakedns',
            ],
            'enabled': true,
            'routeOnly': false,
          },
          'tag': 'http',
        },
    ];

    final outbounds = <Map<String, dynamic>>[
      appliedOutbound,
      {
        'protocol': 'freedom',
        'tag': 'direct',
      },
      {
        'protocol': 'blackhole',
        'tag': 'block',
      },
      {
        'protocol': 'dns',
        'settings': {
          'userLevel': 12,
        },
        'tag': 'dns-out',
      },
    ];

    final dnsSection = _buildEchDns(
      dnsServer: dnsServer,
      domesticDns: domesticDns,
    );

    final jsonMap = <String, dynamic>{
      'dns': dnsSection,
      'fakedns': [
        {
          'ipPool': '198.18.0.0/15',
          'poolSize': 10000,
        },
      ],
      'inbounds': inbounds,
      'log': {
        'loglevel': 'warning',
      },
      'outbounds': outbounds,
      'policy': {
        'levels': {
          '0': {
            'downlinkOnly': 0,
            'uplinkOnly': 0,
          },
          '12': {
            'connIdle': 12,
            'downlinkOnly': 0,
            'uplinkOnly': 0,
          },
        },
      },
      'remarks': finalRemarks,
      'routing': {
        'domainStrategy': 'AsIs',
        'rules': [
          {
            'inboundTag': [
              'socks',
              if (httpPort != null) 'http',
            ],
            'outboundTag': 'dns-out',
            'port': '53',
            'type': 'field',
          },
          {
            'inboundTag': [
              'domestic-dns_0_0',
            ],
            'outboundTag': 'direct',
            'type': 'field',
          },
          {
            'inboundTag': [
              'dns-module',
            ],
            'outboundTag': appliedOutbound['tag'] ?? 'proxy',
            'type': 'field',
          },
          {
            'domain': [
              'domain:ir',
              'geosite:category-ir',
            ],
            'outboundTag': 'direct',
            'type': 'field',
          },
          {
            'ip': [
              'geoip:ir',
            ],
            'outboundTag': 'direct',
            'type': 'field',
          },
        ],
      },
    };

    const encoder = JsonEncoder.withIndent('  ');
    final formatted = encoder.convert(jsonMap);

    return EchResult(
      jsonConfig: jsonMap,
      formattedJson: formatted,
      remarks: finalRemarks,
      protocol: appliedOutbound['protocol']?.toString().toUpperCase() ?? 'PROXY',
      address: effectiveSni,
      port: socksPort,
      network: appliedOutbound['streamSettings']?['network']?.toString().toUpperCase() ?? 'TCP',
      sni: effectiveSni,
      echConfigList: echConfigList,
      fingerprint: fingerprint,
      alpn: alpn,
      proxyCount: 1,
    );
  }

  /// Transforms multiple proxy links or lines into ECH-optimized configurations.
  static List<EchResult> addEchToMultiple(
    List<String> rawInputs, {
    String echConfigList = defaultEchConfigList,
    int socksPort = 10808,
    int? httpPort,
    String dnsServer = defaultDnsServer,
    String domesticDns = defaultDomesticDns,
    String remarkSuffix = '-ech',
    String fingerprint = 'chrome',
    List<String> alpn = const ['http/1.1'],
    bool allowInsecure = false,
  }) {
    final results = <EchResult>[];

    for (final raw in rawInputs) {
      final trimmed = raw.trim();
      if (trimmed.isEmpty) continue;

      if (!trimmed.startsWith('{') && !trimmed.startsWith('[') && trimmed.contains('\n')) {
        final lines = trimmed.split('\n').map((l) => l.trim()).where((l) => l.isNotEmpty);
        for (final line in lines) {
          try {
            results.add(addEchToInput(
              line,
              echConfigList: echConfigList,
              socksPort: socksPort,
              httpPort: httpPort,
              dnsServer: dnsServer,
              domesticDns: domesticDns,
              remarkSuffix: remarkSuffix,
              fingerprint: fingerprint,
              alpn: alpn,
              allowInsecure: allowInsecure,
            ));
          } catch (_) {}
        }
      } else {
        results.add(addEchToInput(
          trimmed,
          echConfigList: echConfigList,
          socksPort: socksPort,
          httpPort: httpPort,
          dnsServer: dnsServer,
          domesticDns: domesticDns,
          remarkSuffix: remarkSuffix,
          fingerprint: fingerprint,
          alpn: alpn,
          allowInsecure: allowInsecure,
        ));
      }
    }

    return results;
  }
}
