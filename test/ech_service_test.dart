import 'package:flutter_test/flutter_test.dart';
import 'package:rdnbenet/core/services/ech_service.dart';

void main() {
  group('EchService Tests', () {
    const dummyVless =
        'vless://11111111-1111-1111-1111-111111111111@server.example.com:443?type=ws&security=tls&path=%2Fws&sni=sni.example.com&fp=chrome#TestNode';

    test('transforms single VLESS link to ECH Xray JSON configuration', () {
      final result = EchService.addEchToInput(
        dummyVless,
        echConfigList: 'cloudflare-ech.com+udp://1.1.1.1',
        socksPort: 10808,
        remarkSuffix: '-ech',
        fingerprint: 'chrome',
      );

      expect(result.remarks, equals('TestNode-ech'));
      expect(result.address, equals('sni.example.com'));
      expect(result.port, equals(10808));
      expect(result.network, equals('WS'));
      expect(result.sni, equals('sni.example.com'));
      expect(result.echConfigList, equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(result.proxyCount, equals(1));

      final json = result.jsonConfig;

      // 1. DNS Section
      final dns = json['dns'] as Map<String, dynamic>;
      expect(dns['tag'], equals('dns-module'));
      final servers = dns['servers'] as List;
      expect(servers.length, equals(3));
      expect(servers[0]['address'], equals('fakedns'));
      expect(servers[1], equals('https://cloudflare-dns.com/dns-query'));
      expect(servers[2]['address'], equals('223.5.5.5'));
      expect(servers[2]['tag'], equals('domestic-dns_0_0'));

      // 2. FakeDNS Section
      final fakedns = json['fakedns'] as List;
      expect(fakedns.length, equals(1));
      expect(fakedns[0]['ipPool'], equals('198.18.0.0/15'));

      // 3. Inbounds Section
      final inbounds = json['inbounds'] as List;
      expect(inbounds.length, equals(1));
      expect(inbounds[0]['port'], equals(10808));
      expect(inbounds[0]['protocol'], equals('socks'));
      final destOverride = inbounds[0]['sniffing']['destOverride'] as List;
      expect(destOverride, contains('fakedns'));

      // 4. Outbounds Section
      final outbounds = json['outbounds'] as List;
      expect(outbounds.length, equals(4)); // proxy + direct + block + dns-out

      final proxy = outbounds[0] as Map<String, dynamic>;
      expect(proxy['tag'], equals('proxy'));
      expect(proxy['protocol'], equals('vless'));
      final streamSettings = proxy['streamSettings'] as Map<String, dynamic>;
      expect(streamSettings['security'], equals('tls'));
      final tlsSettings = streamSettings['tlsSettings'] as Map<String, dynamic>;
      expect(tlsSettings['echConfigList'], equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(tlsSettings['fingerprint'], equals('chrome'));
      expect(tlsSettings['serverName'], equals('sni.example.com'));

      expect(outbounds[1]['tag'], equals('direct'));
      expect(outbounds[2]['tag'], equals('block'));
      expect(outbounds[3]['tag'], equals('dns-out'));
      expect(outbounds[3]['protocol'], equals('dns'));
    });

    test('applies ECH to EACH individual proxy node in a Load Balancer JSON', () {
      const loadBalancerJson = '''
      {
        "remarks": "My-LoadBalancer",
        "observatory": {
          "enableConcurrency": true,
          "probeInterval": "3m",
          "probeUrl": "https://www.google.com/generate_204",
          "subjectSelector": ["proxy-proxy-"]
        },
        "inbounds": [
          {
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "tag": "socks"
          }
        ],
        "outbounds": [
          {
            "tag": "proxy-proxy-1-Alpha",
            "protocol": "vless",
            "settings": {
              "vnext": [{ "address": "alpha.example.com", "port": 443 }]
            },
            "streamSettings": {
              "network": "ws",
              "security": "tls",
              "tlsSettings": { "serverName": "alpha.example.com" }
            }
          },
          {
            "tag": "proxy-proxy-2-Beta",
            "protocol": "trojan",
            "settings": {
              "servers": [{ "address": "beta.example.com", "port": 443 }]
            },
            "streamSettings": {
              "network": "tcp",
              "security": "tls",
              "tlsSettings": { "serverName": "beta.example.com" }
            }
          },
          { "tag": "direct", "protocol": "freedom" },
          { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": {
          "balancers": [
            {
              "selector": ["proxy-proxy-"],
              "strategy": { "type": "leastPing" },
              "tag": "balancer-main"
            }
          ],
          "domainStrategy": "AsIs",
          "rules": [
            {
              "balancerTag": "balancer-main",
              "inboundTag": ["dns-module"],
              "type": "field"
            },
            {
              "balancerTag": "balancer-main",
              "network": "tcp,udp",
              "type": "field"
            }
          ]
        }
      }
      ''';

      final result = EchService.addEchToInput(
        loadBalancerJson,
        echConfigList: 'cloudflare-ech.com+udp://1.1.1.1',
      );

      expect(result.proxyCount, equals(2));
      expect(result.protocol, equals('Load Balancer (2 nodes)'));
      expect(result.remarks, equals('My-LoadBalancer-ech'));

      final json = result.jsonConfig;

      // Both proxy outbounds must have ECH applied
      final outbounds = json['outbounds'] as List;
      final alpha = outbounds.firstWhere((ob) => ob['tag'] == 'proxy-proxy-1-Alpha');
      final beta = outbounds.firstWhere((ob) => ob['tag'] == 'proxy-proxy-2-Beta');

      expect(alpha['streamSettings']['tlsSettings']['echConfigList'], equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(alpha['streamSettings']['tlsSettings']['serverName'], equals('alpha.example.com'));

      expect(beta['streamSettings']['tlsSettings']['echConfigList'], equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(beta['streamSettings']['tlsSettings']['serverName'], equals('beta.example.com'));

      // Observatory & Balancers preserved
      expect(json['observatory'], isNotNull);
      final routing = json['routing'] as Map<String, dynamic>;
      final balancers = routing['balancers'] as List;
      expect(balancers.length, equals(1));
      expect(balancers[0]['tag'], equals('balancer-main'));

      // FakeDNS and dns-out present
      expect(json['fakedns'], isNotNull);
      expect(outbounds.any((ob) => ob['tag'] == 'dns-out'), isTrue);

      // Balancer routing rules for dns-module and tcp,udp present
      final rules = routing['rules'] as List;
      expect(rules.any((r) => r['balancerTag'] == 'balancer-main' && r['inboundTag'] != null), isTrue);
    });

    test('applies ECH to EACH individual hop in a Chain JSON config while preserving dialerProxy', () {
      const chainJson = '''
      {
        "remarks": "Chained: VLESS → TROJAN",
        "outbounds": [
          {
            "tag": "hop0",
            "protocol": "vless",
            "settings": {
              "vnext": [{ "address": "entry.example.com", "port": 443 }]
            },
            "streamSettings": {
              "network": "ws",
              "security": "tls",
              "tlsSettings": { "serverName": "entry.example.com" }
            }
          },
          {
            "tag": "hop1",
            "protocol": "trojan",
            "settings": {
              "servers": [{ "address": "exit.example.com", "port": 443 }]
            },
            "streamSettings": {
              "network": "tcp",
              "security": "tls",
              "sockopt": { "dialerProxy": "hop0" },
              "tlsSettings": { "serverName": "exit.example.com" }
            }
          },
          { "tag": "direct", "protocol": "freedom" },
          { "tag": "block", "protocol": "blackhole" }
        ],
        "routing": {
          "rules": [
            { "type": "field", "outboundTag": "hop1", "port": "0-65535" }
          ]
        }
      }
      ''';

      final result = EchService.addEchToInput(
        chainJson,
        echConfigList: 'cloudflare-ech.com+udp://1.1.1.1',
      );

      expect(result.proxyCount, equals(2));
      expect(result.protocol, equals('Chain (2 hops)'));

      final outbounds = result.jsonConfig['outbounds'] as List;
      final hop0 = outbounds.firstWhere((ob) => ob['tag'] == 'hop0');
      final hop1 = outbounds.firstWhere((ob) => ob['tag'] == 'hop1');

      // Both hops have ECH
      expect(hop0['streamSettings']['tlsSettings']['echConfigList'], equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(hop1['streamSettings']['tlsSettings']['echConfigList'], equals('cloudflare-ech.com+udp://1.1.1.1'));

      // dialerProxy chain is preserved with 100% fidelity
      expect(hop1['streamSettings']['sockopt']['dialerProxy'], equals('hop0'));

      // FakeDNS, dns-out, and routing rules added
      expect(result.jsonConfig['fakedns'], isNotNull);
      expect(outbounds.any((ob) => ob['tag'] == 'dns-out'), isTrue);

      final rules = result.jsonConfig['routing']['rules'] as List;
      expect(rules.any((r) => r['outboundTag'] == 'hop1' && r['inboundTag'] != null && (r['inboundTag'] as List).contains('dns-module')), isTrue);
    });

    test('transforms standalone Xray JSON outbound to ECH configuration', () {
      const standaloneJson = '''
      {
        "tag": "custom-proxy",
        "protocol": "trojan",
        "settings": {
          "servers": [
            {
              "address": "trojan.example.com",
              "port": 443,
              "password": "secret-password"
            }
          ]
        },
        "streamSettings": {
          "network": "tcp",
          "security": "tls",
          "tlsSettings": {
            "serverName": "trojan.example.com"
          }
        }
      }
      ''';

      final result = EchService.addEchToInput(
        standaloneJson,
        echConfigList: 'custom-ech.com+tcp://1.1.1.1',
      );

      final outbounds = result.jsonConfig['outbounds'] as List;
      final proxy = outbounds[0] as Map<String, dynamic>;
      expect(proxy['protocol'], equals('trojan'));
      final tlsSettings = proxy['streamSettings']['tlsSettings'] as Map<String, dynamic>;
      expect(tlsSettings['echConfigList'], equals('custom-ech.com+tcp://1.1.1.1'));
      expect(tlsSettings['serverName'], equals('trojan.example.com'));
    });

    test('supports adding optional HTTP inbound port', () {
      final result = EchService.addEchToInput(
        dummyVless,
        httpPort: 10809,
      );

      final inbounds = result.jsonConfig['inbounds'] as List;
      expect(inbounds.length, equals(2));
      expect(inbounds[1]['port'], equals(10809));
      expect(inbounds[1]['protocol'], equals('http'));

      final routingRules = result.jsonConfig['routing']['rules'] as List;
      expect(routingRules[0]['inboundTag'], contains('http'));
    });

    test('throws FormatException on empty or invalid inputs', () {
      expect(
        () => EchService.addEchToInput(''),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => EchService.addEchToInput('not a valid uri or json'),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
