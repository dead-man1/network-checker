import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:rdnbenet/features/patt/add_ech/add_ech_controller.dart';
import 'package:rdnbenet/features/patt/add_ech/add_ech_screen.dart';

void main() {
  testWidgets('AddEchScreen renders and handles user interactions', (tester) async {
    tester.view.physicalSize = const Size(1200, 1600);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    final controller = AddEchController();

    await tester.pumpWidget(
      MaterialApp(
        home: ChangeNotifierProvider<AddEchController>.value(
          value: controller,
          child: const AddEchScreen(),
        ),
      ),
    );

    // Verify header and UI elements
    expect(find.text('Add ECH'), findsOneWidget);
    expect(find.text('Encrypted Client Hello (ECH)'), findsOneWidget);
    expect(find.text('Input Proxy Config or Share Link'), findsOneWidget);
    expect(find.text('Add ECH & Generate JSON'), findsOneWidget);

    // Tap Sample button
    await tester.tap(find.text('Sample'));
    await tester.pumpAndSettle();

    expect(controller.inputText, isNotEmpty);

    // Tap Add ECH & Generate JSON
    await tester.tap(find.text('Add ECH & Generate JSON'));
    await tester.pumpAndSettle();

    // Verify output section is rendered
    expect(find.text('ECH-Enabled Xray JSON Profile'), findsOneWidget);
    expect(find.text('Copy'), findsOneWidget);

    // Toggle settings icon in AppBar
    await tester.tap(find.byIcon(Icons.tune_outlined));
    await tester.pumpAndSettle();

    expect(find.text('ECH & TLS Settings'), findsOneWidget);
    expect(find.text('ECH Config List'), findsOneWidget);
  });
}
