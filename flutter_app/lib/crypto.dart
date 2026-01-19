import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

class IndigoCrypto {
  static final ecdh = Ecdh.p256(Length.retained);
  static final aes = AesGcm.with256bits();
  static final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  // Generate Key Pair
  static Future<SimpleKeyPair> generateKeys() async {
    return await ecdh.newKeyPair();
  }

  // Decrypt Payload (ECIES: ECDH -> HKDF -> AES-GCM)
  static Future<List<int>> decrypt(
      SimpleKeyPair keyPair, List<int> encryptedBlob) async {
    // Blob Format: EphemeralPubKey (65) + IV (12) + Ciphertext + Tag (16)
    if (encryptedBlob.length < 93) throw Exception("Invalid blob size");

    // 1. Extract Ephemeral Public Key (Uncompressed P-256: 0x04 + X + Y)
    // First 65 bytes
    final ephemeralBytes = encryptedBlob.sublist(0, 65);
    if (ephemeralBytes[0] != 0x04) throw Exception("Invalid key format");

    final x = ephemeralBytes.sublist(1, 33);
    final y = ephemeralBytes.sublist(33, 65);
    final ephemeralKey = SimplePublicKey(ephemeralBytes, type: KeyPairType.p256, x: x, y: y);

    // 2. Extract IV (12 bytes)
    final iv = encryptedBlob.sublist(65, 77);

    // 3. Extract Tag (Last 16 bytes)
    final tag = encryptedBlob.sublist(encryptedBlob.length - 16);

    // 4. Extract Ciphertext
    final ciphertext = encryptedBlob.sublist(77, encryptedBlob.length - 16);

    // 5. Derive Shared Secret (ECDH)
    final sharedSecret = await ecdh.sharedSecretKey(
      keyPair: keyPair,
      remotePublicKey: ephemeralKey,
    );
    final sharedBytes = await sharedSecret.extractBytes();

    // 6. Derive AES Key (HKDF)
    // Salt (nonce) must be 32 bytes of zeros to match Python's salt=None
    final aesKeyMaterial = await hkdf.deriveKey(
      secretKey: SecretKey(sharedBytes),
      nonce: List.filled(32, 0),
      info: utf8.encode('mfa-protocol-encryption'),
    );

    // 7. Decrypt (AES-GCM)
    final secretBox = SecretBox(ciphertext, nonce: iv, mac: Mac(tag));
    final clearText = await aes.decrypt(
      secretBox,
      secretKey: aesKeyMaterial,
    );

    return clearText;
  }

  // Export Public Key to PEM (SubjectPublicKeyInfo for P-256)
  static Future<String> getPublicKeyPem(SimpleKeyPair keyPair) async {
    final pubKey = await keyPair.extractPublicKey();
    final x = pubKey.x;
    final y = pubKey.y;

    // ASN.1 Header for P-256
    // Sequence(Sequence(Oid(ecPublicKey), Oid(prime256v1)), BitString(0x04 + X + Y))
    final header = [
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    ];

    final body = [0x04, ...x, ...y];
    final allBytes = [...header, ...body];

    final b64 = base64.encode(allBytes);
    return "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----";
  }

  // Persist Key
  static Future<String> encodePrivateKey(SimpleKeyPair keyPair) async {
    final bytes = await keyPair.extractPrivateKeyBytes();
    return base64.encode(bytes);
  }

  // Load Key
  static Future<SimpleKeyPair> decodePrivateKey(String b64) async {
    final bytes = base64.decode(b64);
    return await ecdh.newKeyPairFromSeed(bytes);
  }
}
