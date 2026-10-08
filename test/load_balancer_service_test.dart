import 'package:flutter_test/flutter_test.dart';
import 'package:rdnbenet/core/services/load_balancer_service.dart';

void main() {
  group('LoadBalancerService Tests', () {
    test('sanitizeTag cleans invalid characters and strips underscores', () {
      expect(LoadBalancerService.sanitizeTag('  my-node_test  '), equals('my-node_test'));
      expect(LoadBalancerService.sanitizeTag('my@node#1!'), equals('my_node_1'));
      expect(LoadBalancerService.sanitizeTag('___clean_me___'), equals('clean_me'));
      expect(LoadBalancerService.sanitizeTag(''), equals(''));
    });

    test('generates least-ping balancer configuration from share links (URIs)', () {
      const vlessLink1 = 'vless://11111111-1111-1111-1111-111111111111@node1.example.com:443?security=tls&type=ws&sni=node1.example.com&path=/ws#Server-Alpha';
      const trojanLink2 = 'trojan://secretpassword@node2.example.com:443?security=tls&type=tcp&sni=node2.example.com#Server-Beta';

      final profile = LoadBalancerService.generateBalancerProfile(
        inputs: [vlessLink1, trojanLink2],
        remarks: 'my-balancer',
        socksPort: 10808,
        httpPort: 10809,
        probeUrl: 'https://cp.cloudflare.com/generate_204',
        probeInterval: '2m',
        strategyType: 'leastPing',
      );

      expect(profile['remarks'], equals('my-balancer'));

      // DNS
      final dns = profile['dns'] as Map<String, dynamic>;
      expect(dns['tag'], equals('dns-module'));
      expect(dns['servers'], equals(['1.1.1.1']));

      // Inbounds
      final inbounds = profile['inbounds'] as List;
      expect(inbounds.length, equals(2));
      expect(inbounds[0]['port'], equals(10808));
      expect(inbounds[0]['protocol'], equals('socks'));
      expect(inbounds[1]['port'], equals(10809));
      expect(inbounds[1]['protocol'], equals('http'));

      // Observatory
      final obs = profile['observatory'] as Map<String, dynamic>;
      expect(obs['probeUrl'], equals('https://cp.cloudflare.com/generate_204'));
      expect(obs['probeInterval'], equals('2m'));
      expect(obs['enableConcurrency'], isTrue);
      expect(obs['subjectSelector'], equals(['proxy-proxy-']));

      // Outbounds
      final outbounds = profile['outbounds'] as List;
      expect(outbounds.length, equals(4)); // 2 proxies + direct + block
      expect(outbounds[0]['tag'], equals('proxy-proxy-1-Server-Alpha'));
      expect(outbounds[0]['protocol'], equals('vless'));
      expect(outbounds[1]['tag'], equals('proxy-proxy-2-Server-Beta'));
      expect(outbounds[1]['protocol'], equals('trojan'));
      expect(outbounds[2]['tag'], equals('direct'));
      expect(outbounds[2]['protocol'], equals('freedom'));
      expect(outbounds[3]['tag'], equals('block'));
      expect(outbounds[3]['protocol'], equals('blackhole'));

      // Routing
      final routing = profile['routing'] as Map<String, dynamic>;
      final balancers = routing['balancers'] as List;
      expect(balancers.length, equals(1));
      expect(balancers[0]['tag'], equals('balancer-main'));
      expect(balancers[0]['selector'], equals(['proxy-proxy-']));
      expect(balancers[0]['strategy']['type'], equals('leastPing'));

      final rules = routing['rules'] as List;
      expect(rules.length, equals(2));
      expect(rules[0]['balancerTag'], equals('balancer-main'));
      expect(rules[0]['inboundTag'], equals(['dns-module']));
      expect(rules[1]['balancerTag'], equals('balancer-main'));
      expect(rules[1]['network'], equals('tcp,udp'));

      // Policy & Log
      expect(profile['policy'], isNotNull);
      expect(profile['log'], isNotNull);
    });

    test('generates balancer configuration from full Xray JSON configs merging DNS and inbounds', () {
      const xrayJson1 = '''
      {
        "remarks": "Config1",
        "dns": {
          "hosts": {
            "dns.example.com": ["1.1.1.1", "1.0.0.1"],
            "test.com": "9.9.9.9"
          },
          "servers": ["8.8.8.8"]
        },
        "inbounds": [
          {
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {
              "auth": "noauth",
              "udp": false,
              "userLevel": 8
            },
            "tag": "socks"
          }
        ],
        "outbounds": [
          {
            "protocol": "vless",
            "settings": {
              "vnext": [
                {
                  "address": "proxy1.example.com",
                  "port": 443,
                  "users": [
                    { "id": "11111111-2222-3333-4444-555555555555" }
                  ]
                }
              ]
            },
            "tag": "proxy-alpha"
          },
          {
            "protocol": "freedom",
            "tag": "direct"
          }
        ]
      }
      ''';

      const xrayJson2 = '''
      {
        "remarks": "Config2",
        "dns": {
          "hosts": {
            "dns.example.com": ["1.1.1.1", "2.2.2.2"],
            "extra.org": "1.2.3.4"
          },
          "servers": ["1.1.1.1"]
        },
        "outbounds": [
          {
            "protocol": "vmess",
            "settings": {
              "vnext": [
                {
                  "address": "proxy2.example.com",
                  "port": 443,
                  "users": [
                    { "id": "22222222-3333-4444-5555-666666666666" }
                  ]
                }
              ]
            },
            "tag": "proxy-beta"
          }
        ]
      }
      ''';

      final profile = LoadBalancerService.generateBalancerProfile(
        inputs: [xrayJson1, xrayJson2],
      );

      // DNS merging verification
      final dns = profile['dns'] as Map<String, dynamic>;
      final hosts = dns['hosts'] as Map<String, dynamic>;
      expect(hosts['test.com'], equals('9.9.9.9'));
      expect(hosts['extra.org'], equals('1.2.3.4'));
      expect(hosts['dns.example.com'], contains('1.1.1.1'));
      expect(hosts['dns.example.com'], contains('1.0.0.1'));
      expect(hosts['dns.example.com'], contains('2.2.2.2'));

      final servers = dns['servers'] as List;
      expect(servers, contains('8.8.8.8'));
      expect(servers, contains('1.1.1.1'));

      // Outbounds tagging
      final outbounds = profile['outbounds'] as List;
      expect(outbounds.length, equals(4)); // 2 proxies + direct + block
      expect(outbounds[0]['tag'], equals('proxy-proxy-1-proxy-alpha'));
      expect(outbounds[0]['protocol'], equals('vless'));
      expect(outbounds[1]['tag'], equals('proxy-proxy-2-proxy-beta'));
      expect(outbounds[1]['protocol'], equals('vmess'));
    });

    test('handles multi-line pasted share links in a single input string', () {
      const multiLineInput = '''
      vless://11111111-1111-1111-1111-111111111111@node1.example.com:443?security=tls#Node-1
      vless://22222222-2222-2222-2222-222222222222@node2.example.com:443?security=tls#Node-2
      ''';

      final profile = LoadBalancerService.generateBalancerProfile(
        inputs: [multiLineInput],
      );

      final outbounds = profile['outbounds'] as List;
      expect(outbounds.length, equals(4)); // 2 proxies + direct + block
      expect(outbounds[0]['tag'], equals('proxy-proxy-1-Node-1'));
      expect(outbounds[1]['tag'], equals('proxy-proxy-2-Node-2'));
    });

    test('throws FormatException when no valid inputs or proxies provided', () {
      expect(
        () => LoadBalancerService.generateBalancerProfile(inputs: []),
        throwsA(isA<FormatException>()),
      );

      expect(
        () => LoadBalancerService.generateBalancerProfile(inputs: ['   ']),
        throwsA(isA<FormatException>()),
      );
    });
  });
}
