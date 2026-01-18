import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  final String baseUrl;
  final String tenantId;

  ApiService(this.baseUrl, this.tenantId);

  Future<void> register(String userId, String pubKeyPem) async {
    final resp = await http.post(
      Uri.parse('$baseUrl/register'),
      headers: {'Content-Type': 'application/json', 'X-Tenant-ID': tenantId},
      body: jsonEncode({
        'user_id': userId,
        'public_key_pem_hex': _strToHex(pubKeyPem),
        'push_endpoint': ''
      }),
    );
    _checkResponse(resp, "Registration");
  }

  Future<String> getChallenge(String userId) async {
    final resp = await http.post(
      Uri.parse('$baseUrl/auth/challenge'),
      headers: {'Content-Type': 'application/json', 'X-Tenant-ID': tenantId},
      body: jsonEncode({'user_id': userId}),
    );
    _checkResponse(resp, "Challenge");

    final data = jsonDecode(resp.body);
    return data['encrypted_challenge_hex'];
  }

  Future<void> verify(String userId, String otp) async {
    final resp = await http.post(
      Uri.parse('$baseUrl/auth/verify'),
      headers: {'Content-Type': 'application/json', 'X-Tenant-ID': tenantId},
      body: jsonEncode({'user_id': userId, 'otp': otp}),
    );
    _checkResponse(resp, "Verification");
  }

  void _checkResponse(http.Response resp, String action) {
    if (resp.statusCode >= 200 && resp.statusCode < 300) return;

    if (resp.statusCode == 403) {
      // Check for Retry-After
      if (resp.headers.containsKey('retry-after')) {
        final wait = resp.headers['retry-after'];
        throw Exception('$action Locked: Please wait ${wait}s before retrying.');
      }
    }

    String errorMsg = resp.body;
    try {
      final json = jsonDecode(resp.body);
      if (json is Map && (json.containsKey('error') || json.containsKey('message'))) {
        errorMsg = json['error'] ?? json['message'];
      }
    } catch (_) {}

    throw Exception('$action failed: $errorMsg');
  }

  String _strToHex(String input) {
    return utf8.encode(input).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
