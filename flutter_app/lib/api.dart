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
    if (resp.statusCode != 200 && resp.statusCode != 201) {
      throw Exception('Registration failed: ${resp.body}');
    }
  }

  Future<String> getChallenge(String userId) async {
    final resp = await http.post(
      Uri.parse('$baseUrl/auth/challenge'),
      headers: {'Content-Type': 'application/json', 'X-Tenant-ID': tenantId},
      body: jsonEncode({'user_id': userId}),
    );
    if (resp.statusCode != 200) {
      throw Exception('Challenge failed: ${resp.body}');
    }
    final data = jsonDecode(resp.body);
    return data['encrypted_challenge_hex'];
  }

  Future<void> verify(String userId, String otp) async {
    final resp = await http.post(
      Uri.parse('$baseUrl/auth/verify'),
      headers: {'Content-Type': 'application/json', 'X-Tenant-ID': tenantId},
      body: jsonEncode({'user_id': userId, 'otp': otp}),
    );
    if (resp.statusCode != 200) {
      throw Exception('Verification failed: ${resp.body}');
    }
  }

  String _strToHex(String input) {
    return utf8.encode(input).map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
