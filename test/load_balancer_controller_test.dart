import 'package:flutter_test/flutter_test.dart';
import 'package:rdnbenet/features/load_balancer/load_balancer_controller.dart';

void main() {
  group('LoadBalancerController Tests', () {
    test('initializes with default state', () {
      final controller = LoadBalancerController();
      expect(controller.inputConfigs.length, equals(2));
      expect(controller.socksPort, equals(10808));
      expect(controller.httpPort, equals(10809));
      expect(controller.strategyType, equals('leastPing'));
      expect(controller.probeUrl, equals('https://www.google.com/generate_204'));
      expect(controller.probeInterval, equals('3m'));
      expect(controller.enableConcurrency, isTrue);
      expect(controller.remarks, equals('leastping'));
      expect(controller.generatedJson, isNull);
      expect(controller.errorMessage, isNull);
      expect(controller.isGenerating, isFalse);
    });

    test('add, set, remove, and clear input configs', () {
      final controller = LoadBalancerController();

      controller.setInputConfig(0, 'vless://node1@test.com:443');
      expect(controller.inputConfigs[0], equals('vless://node1@test.com:443'));

      controller.addInputConfig('vmess://node2@test.com:443');
      expect(controller.inputConfigs.length, equals(3));
      expect(controller.inputConfigs[2], equals('vmess://node2@test.com:443'));

      controller.removeInputConfig(1);
      expect(controller.inputConfigs.length, equals(2));
      expect(controller.inputConfigs[1], equals('vmess://node2@test.com:443'));

      controller.clear();
      expect(controller.inputConfigs.length, equals(2));
      expect(controller.inputConfigs[0], isEmpty);
      expect(controller.inputConfigs[1], isEmpty);
    });

    test('addBulkInputs adds multiple lines', () {
      final controller = LoadBalancerController();
      const bulk = '''
      vless://node1@test.com:443#N1
      trojan://pass@test.com:443#N2
      ss://method:pass@test.com:443#N3
      ''';

      controller.addBulkInputs(bulk);
      expect(controller.inputConfigs.length, equals(3));
      expect(controller.inputConfigs[0], contains('node1@test.com:443#N1'));
      expect(controller.inputConfigs[1], contains('pass@test.com:443#N2'));
      expect(controller.inputConfigs[2], contains('method:pass@test.com:443#N3'));
    });

    test('generateBalancer sets errorMessage when inputs are empty', () async {
      final controller = LoadBalancerController();
      await controller.generateBalancer();

      expect(controller.errorMessage, isNotNull);
      expect(controller.generatedJson, isNull);
    });

    test('generateBalancer successfully creates JSON profile with valid inputs', () async {
      final controller = LoadBalancerController();
      controller.setInputConfig(0, 'vless://11111111-1111-1111-1111-111111111111@node1.test.com:443?security=tls#NodeA');
      controller.setInputConfig(1, 'trojan://password123@node2.test.com:443?security=tls#NodeB');

      await controller.generateBalancer();

      expect(controller.errorMessage, isNull);
      expect(controller.generatedJson, isNotNull);
      expect(controller.generatedJson, contains('"tag": "proxy-proxy-1-NodeA"'));
      expect(controller.generatedJson, contains('"tag": "proxy-proxy-2-NodeB"'));
      expect(controller.generatedJson, contains('"tag": "balancer-main"'));
      expect(controller.generatedJson, contains('"probeUrl": "https://www.google.com/generate_204"'));
    });

    test('updating configuration settings affects output', () async {
      final controller = LoadBalancerController();
      controller.setInputConfig(0, 'vless://11111111-1111-1111-1111-111111111111@node1.test.com:443?security=tls#NodeA');
      controller.setProbeUrl('https://custom.probe.url/generate_204');
      controller.setProbeInterval('1m');
      controller.setStrategyType('roundRobin');
      controller.setRemarks('my-custom-balancer');
      controller.setSocksPort(20808);
      controller.setHttpPort(20809);
      controller.setEnableConcurrency(false);

      await controller.generateBalancer();

      expect(controller.errorMessage, isNull);
      final json = controller.generatedJson!;
      expect(json, contains('"probeUrl": "https://custom.probe.url/generate_204"'));
      expect(json, contains('"probeInterval": "1m"'));
      expect(json, contains('"type": "roundRobin"'));
      expect(json, contains('"remarks": "my-custom-balancer"'));
      expect(json, contains('"port": 20808'));
      expect(json, contains('"port": 20809'));
      expect(json, contains('"enableConcurrency": false'));
    });
  });
}
