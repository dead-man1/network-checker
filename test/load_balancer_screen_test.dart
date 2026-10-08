import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:rdnbenet/features/load_balancer/load_balancer_controller.dart';
import 'package:rdnbenet/features/load_balancer/load_balancer_screen.dart';

void main() {
  testWidgets('LoadBalancerScreen renders properly and handles user interaction', (tester) async {
    // Set a large screen size for test environment
    tester.view.physicalSize = const Size(1200, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = LoadBalancerController();

    await tester.pumpWidget(
      MaterialApp(
        home: ChangeNotifierProvider<LoadBalancerController>.value(
          value: controller,
          child: const LoadBalancerScreen(),
        ),
      ),
    );

    // Verify title and headers render
    expect(find.text('Load Balancer'), findsOneWidget);
    expect(find.text('Xray Least-Ping Load Balancer'), findsOneWidget);
    expect(find.text('Proxy Nodes'), findsOneWidget);
    expect(find.text('Node #1'), findsOneWidget);
    expect(find.text('Node #2'), findsOneWidget);
    expect(find.text('Balancer & Observatory Settings'), findsOneWidget);
    expect(find.text('Local Inbound Ports'), findsOneWidget);
    expect(find.text('Generate Balancer Config'), findsOneWidget);

    // Tap Add Node Slot
    await tester.ensureVisible(find.text('Add Node Slot'));
    await tester.tap(find.text('Add Node Slot'));
    await tester.pumpAndSettle();

    expect(find.text('Node #3'), findsOneWidget);
    expect(controller.inputConfigs.length, equals(3));

    // Tap Bulk Import button
    await tester.ensureVisible(find.text('Bulk Import'));
    await tester.tap(find.text('Bulk Import'));
    await tester.pumpAndSettle();

    expect(find.text('Bulk Import Configs / URIs'), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
  });
}
