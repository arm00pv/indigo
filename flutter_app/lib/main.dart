import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:cryptography/cryptography.dart';
import 'crypto.dart';
import 'api.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Indigo Authenticator',
      theme: ThemeData(primarySwatch: Colors.indigo),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final storage = const FlutterSecureStorage();
  final _smartCodeController = TextEditingController();
  final _pinController = TextEditingController();
  final _setupPinController = TextEditingController();
  final _setupDuressController = TextEditingController();

  String _status = "Initialize Configuration";

  // Config
  String? userId;
  String? baseUrl;
  String? tenantId = "default";

  // Keys (In memory for demo - use secure storage in prod)
  SimpleKeyPair? _keyPair;

  @override
  void initState() {
    super.initState();
    _loadConfig();
  }

  Future<void> _loadConfig() async {
    userId = await storage.read(key: 'user_id');
    baseUrl = await storage.read(key: 'base_url');
    tenantId = await storage.read(key: 'tenant_id') ?? "default";

    // Check for keys
    if (userId != null && baseUrl != null) {
        final keyStr = await storage.read(key: 'private_key');
        if (keyStr != null) {
             _keyPair = await IndigoCrypto.decodePrivateKey(keyStr);
             setState(() { _status = "Ready for: $userId"; });
        } else {
             setState(() { _status = "Keys missing. Please Setup again."; });
        }
    }
  }

  Future<void> _setupFromSmartCode() async {
    final code = _smartCodeController.text.trim();
    final pin = _setupPinController.text.trim();
    final duress = _setupDuressController.text.trim();

    if (code.isEmpty) return;
    if (pin.length < 4) {
        setState(() { _status = "PIN must be 4+ digits"; });
        return;
    }

    try {
        final algo = Sha256();
        final pinHash = await algo.hash(utf8.encode(pin));
        await storage.write(key: 'pin_hash', value: base64.encode(pinHash.bytes));

        if (duress.isNotEmpty) {
            final duressHash = await algo.hash(utf8.encode(duress));
            await storage.write(key: 'duress_hash', value: base64.encode(duressHash.bytes));
        }

        final jsonStr = utf8.decode(base64.decode(code));
        final data = jsonDecode(jsonStr);

        await storage.write(key: 'user_id', value: data['user_id']);
        await storage.write(key: 'base_url', value: data['url']);
        await storage.write(key: 'tenant_id', value: data['tenant_id']);

        // Generate Keys
        _keyPair = await IndigoCrypto.generateKeys();
        final pubPem = await IndigoCrypto.getPublicKeyPem(_keyPair!);

        // Save Keys
        final keyStr = await IndigoCrypto.encodePrivateKey(_keyPair!);
        await storage.write(key: 'private_key', value: keyStr);

        // Register
        final api = ApiService(data['url'], data['tenant_id']);
        await api.register(data['user_id'], pubPem);

        _loadConfig();
        setState(() { _status = "Registered & Ready"; });
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Setup Successful")));

    } catch (e) {
        final msg = e.toString().replaceAll("Exception: ", "");
        setState(() { _status = "Error: $msg"; });
        if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg), backgroundColor: Colors.red));
        }
    }
  }

  Future<void> _login() async {
    if (_keyPair == null || baseUrl == null) return;

    try {
        final api = ApiService(baseUrl!, tenantId!);

        // 1. Get Challenge
        final encryptedHex = await api.getChallenge(userId!);
        final encryptedBytes = _hexToBytes(encryptedHex);

        // 2. Decrypt
        final decryptedBytes = await IndigoCrypto.decrypt(_keyPair!, encryptedBytes);
        final plaintext = utf8.decode(decryptedBytes);

        String otp = plaintext;
        String? contextMsg;

        // 3. Parse Context (JSON)
        try {
            if (plaintext.trim().startsWith('{')) {
                final data = jsonDecode(plaintext);
                otp = data['otp'];
                contextMsg = data['context'];
            }
        } catch (_) {}

        // 4. Show Context Dialog
        if (contextMsg != null) {
            final approved = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                    title: const Text("⚠️ Action Verification"),
                    content: Text("Context: $contextMsg\n\nDo you verify this?"),
                    actions: [
                        TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text("Reject")),
                        TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text("Approve")),
                    ],
                )
            );
            if (approved != true) return;
        }

        // 5. Duress Check & PIN Verification
        final pin = _pinController.text;
        final algo = Sha256();
        final pinHash = base64.encode((await algo.hash(utf8.encode(pin))).bytes);

        final storedPin = await storage.read(key: 'pin_hash');
        final storedDuress = await storage.read(key: 'duress_hash');

        bool isDuress = false;

        if (storedPin != null && pinHash == storedPin) {
            // Valid
        } else if (storedDuress != null && pinHash == storedDuress) {
            isDuress = true;
        } else if (storedPin == null && pin == "9999") {
            // Legacy Simulation (if no PIN set)
            isDuress = true;
        } else if (storedPin == null) {
            // Allow if no PIN set
        } else {
            throw Exception("Invalid PIN");
        }

        if (isDuress) {
            // Modify OTP (Mod 10 Logic)
            final lastDigit = int.parse(otp.substring(otp.length - 1));
            final newLast = (lastDigit + 1) % 10;
            otp = otp.substring(0, otp.length - 1) + newLast.toString();
            print("DURESS MODE ACTIVE");
        }

        // 6. Submit
        await api.verify(userId!, otp);
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text("Authentication Successful")));

    } catch (e) {
        final msg = e.toString().replaceAll("Exception: ", "");
        setState(() { _status = "Auth Error: $msg"; });
        if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg), backgroundColor: Colors.red));
        }
    }
  }

  List<int> _hexToBytes(String hex) {
    var result = <int>[];
    for (var i = 0; i < hex.length; i += 2) {
      result.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return result;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Indigo MFA")),
      body: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            Text("Status: $_status", style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 20),
            if (userId == null) ...[
                TextField(
                    controller: _smartCodeController,
                    decoration: const InputDecoration(labelText: "Paste Smart Code (Base64)"),
                ),
                const SizedBox(height: 10),
                TextField(
                    controller: _setupPinController,
                    decoration: const InputDecoration(labelText: "Create App PIN (4+ digits)"),
                    obscureText: true,
                    keyboardType: TextInputType.number,
                ),
                TextField(
                    controller: _setupDuressController,
                    decoration: const InputDecoration(labelText: "Create Duress PIN (Optional)"),
                    obscureText: true,
                    keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 10),
                ElevatedButton(onPressed: _setupFromSmartCode, child: const Text("Setup"))
            ] else ...[
                TextField(
                    controller: _pinController,
                    decoration: const InputDecoration(labelText: "Enter PIN (9999 for Duress)"),
                    obscureText: true,
                    keyboardType: TextInputType.number,
                ),
                const SizedBox(height: 20),
                ElevatedButton(onPressed: _login, child: const Text("Login / Authenticate")),
            ]
          ],
        ),
      ),
    );
  }
}
