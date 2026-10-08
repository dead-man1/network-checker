import 'package:flutter_test/flutter_test.dart';
import 'package:rdnbenet/features/patt/add_ech/add_ech_controller.dart';

void main() {
  group('AddEchController Tests', () {
    const dummyVless =
        'vless://11111111-1111-1111-1111-111111111111@server.example.com:443?type=ws&security=tls&path=%2Fws&sni=sni.example.com&fp=chrome#TestNode';

    test('initializes with default settings', () {
      final controller = AddEchController();
      expect(controller.inputText, isEmpty);
      expect(controller.echConfigList, equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(controller.socksPort, equals(10808));
      expect(controller.httpPort, equals(10809));
      expect(controller.dnsServer, equals('https://cloudflare-dns.com/dns-query'));
      expect(controller.domesticDns, equals('223.5.5.5'));
      expect(controller.remarkSuffix, equals('-ech'));
      expect(controller.fingerprint, equals('chrome'));
      expect(controller.alpnText, equals('http/1.1'));
      expect(controller.allowInsecure, isFalse);
      expect(controller.results, isEmpty);
      expect(controller.errorMessage, isNull);
    });

    test('transforms valid VLESS link and populates results', () {
      final controller = AddEchController();
      controller.setInputText(dummyVless);
      controller.transform();

      expect(controller.errorMessage, isNull);
      expect(controller.results.length, equals(1));
      final res = controller.currentResult!;
      expect(res.remarks, equals('TestNode-ech'));
      expect(res.echConfigList, equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(res.formattedJson, contains('"echConfigList": "cloudflare-ech.com+udp://1.1.1.1"'));
      expect(res.formattedJson, contains('"address": "fakedns"'));
    });

    test('handles empty input gracefully with error message', () {
      final controller = AddEchController();
      controller.setInputText('   ');
      controller.transform();

      expect(controller.errorMessage, isNotNull);
      expect(controller.results, isEmpty);
    });

    test('resetToDefaults resets customized settings', () {
      final controller = AddEchController();
      controller.setSocksPort(20808);
      controller.setFingerprint('firefox');
      controller.setEchConfigList('custom-ech.com');
      controller.setAllowInsecure(true);

      controller.resetToDefaults();
      expect(controller.socksPort, equals(10808));
      expect(controller.fingerprint, equals('chrome'));
      expect(controller.echConfigList, equals('cloudflare-ech.com+udp://1.1.1.1'));
      expect(controller.allowInsecure, isFalse);
    });

    test('clear resets input and results', () {
      final controller = AddEchController();
      controller.setInputText(dummyVless);
      controller.transform();
      expect(controller.results.length, equals(1));

      controller.clear();
      expect(controller.inputText, isEmpty);
      expect(controller.results, isEmpty);
      expect(controller.errorMessage, isNull);
    });
  });
}
