import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:rdnbenet/core/services/proxy_parser_service.dart';

void main() {
  group('ProxyParserService Tests', () {
    test('parses VLESS share link correctly', () {
      const link =
          'vless://00000000-0000-0000-0000-000000000001@entry.example.com:443?type=ws&security=tls&path=%2Fentry-path&sni=entry.example.com#MyEntry';
      final node = ProxyParserService.parseLink(link);

      expect(node.protocol, equals('vless'));
      expect(node.address, equals('entry.example.com'));
      expect(node.port, equals(443));
      expect(node.idOrPassword, equals('00000000-0000-0000-0000-000000000001'));
      expect(node.network, equals('ws'));
      expect(node.security, equals('tls'));
      expect(node.path, equals('/entry-path'));
      expect(node.sni, equals('entry.example.com'));
      expect(node.remarks, equals('MyEntry'));
    });

    test('parses Trojan share link correctly', () {
      const link =
          'trojan://mysecretpass@exit.example.com:8443?security=tls&sni=exit.example.com&type=grpc&serviceName=mygrpc#MyTrojan';
      final node = ProxyParserService.parseLink(link);

      expect(node.protocol, equals('trojan'));
      expect(node.address, equals('exit.example.com'));
      expect(node.port, equals(8443));
      expect(node.idOrPassword, equals('mysecretpass'));
      expect(node.network, equals('grpc'));
      expect(node.security, equals('tls'));
      expect(node.serviceName, equals('mygrpc'));
      expect(node.remarks, equals('MyTrojan'));
    });

    test('parses VMess base64 JSON share link correctly', () {
      final vmessJson = {
        'v': '2',
        'ps': 'VMessExit',
        'add': 'vmess.example.com',
        'port': 2096,
        'id': '00000000-0000-0000-0000-000000000002',
        'aid': 0,
        'scy': 'auto',
        'net': 'ws',
        'path': '/vmess-ws',
        'tls': 'tls',
        'sni': 'vmess.example.com'
      };
      final base64Str = base64.encode(utf8.encode(json.encode(vmessJson)));
      final link = 'vmess://$base64Str';

      final node = ProxyParserService.parseLink(link);

      expect(node.protocol, equals('vmess'));
      expect(node.address, equals('vmess.example.com'));
      expect(node.port, equals(2096));
      expect(node.idOrPassword, equals('00000000-0000-0000-0000-000000000002'));
      expect(node.network, equals('ws'));
      expect(node.security, equals('tls'));
      expect(node.path, equals('/vmess-ws'));
      expect(node.remarks, equals('VMessExit'));
    });

    test('generates 2-hop chained Xray profile with dialerProxy', () {
      const entryLink =
          'vless://00000000-0000-0000-0000-000000000001@entry.example.com:443?type=ws&security=tls&path=%2Fentry-path#Entry';
      const exitLink =
          'vless://00000000-0000-0000-0000-000000000002@exit.example.com:443?type=ws&security=tls&path=%2Fexit-path#Exit';

      final profiles = ProxyParserService.generateChainProfile(
        nodeShareLinks: [entryLink, exitLink],
        socksPort: 10808,
        httpPort: 10809,
      );

      expect(profiles.length, equals(1));
      final profile = profiles.first;

      expect(profile['remarks'], contains('VLESS (Entry) → VLESS (Exit)'));

      final outbounds = profile['outbounds'] as List;
      expect(outbounds.length, equals(4)); // hop0, hop1, direct, block

      final hop0 = outbounds[0] as Map<String, dynamic>;
      expect(hop0['tag'], equals('hop0'));
      expect(hop0['protocol'], equals('vless'));
      final hop0Stream = hop0['streamSettings'] as Map<String, dynamic>;
      expect(hop0Stream.containsKey('sockopt'), isFalse);

      final hop1 = outbounds[1] as Map<String, dynamic>;
      expect(hop1['tag'], equals('hop1'));
      expect(hop1['protocol'], equals('vless'));
      final hop1Stream = hop1['streamSettings'] as Map<String, dynamic>;
      expect(hop1Stream['sockopt']['dialerProxy'], equals('hop0'));

      final routing = profile['routing'] as Map<String, dynamic>;
      final rules = routing['rules'] as List;
      expect(rules.first['outboundTag'], equals('hop1'));
    });

    test('generates 3-hop chained Xray profile correctly', () {
      const node0 =
          'vless://uuid0@node0.com:443?type=ws&security=tls#Node0';
      const node1 =
          'trojan://pass1@node1.com:443?security=tls#Node1';
      const node2 =
          'vless://uuid2@node2.com:443?type=grpc&security=tls#Node2';

      final profiles = ProxyParserService.generateChainProfile(
        nodeShareLinks: [node0, node1, node2],
      );

      final outbounds = profiles.first['outbounds'] as List;
      expect(outbounds.length, equals(5)); // hop0, hop1, hop2, direct, block

      final hop0 = outbounds[0] as Map<String, dynamic>;
      final hop1 = outbounds[1] as Map<String, dynamic>;
      final hop2 = outbounds[2] as Map<String, dynamic>;

      expect(hop0['streamSettings'].containsKey('sockopt'), isFalse);
      expect(hop1['streamSettings']['sockopt']['dialerProxy'], equals('hop0'));
      expect(hop2['streamSettings']['sockopt']['dialerProxy'], equals('hop1'));

      final rules = profiles.first['routing']['rules'] as List;
      expect(rules.first['outboundTag'], equals('hop2'));
    });

    test('throws FormatException when less than 2 links are provided', () {
      expect(
        () => ProxyParserService.generateChainProfile(nodeShareLinks: ['vless://uuid@host:443']),
        throwsFormatException,
      );
    });

    test('throws FormatException on unsupported protocol link', () {
      expect(
        () => ProxyParserService.parseLink('ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388'),
        throwsFormatException,
      );
    });
  });
}
