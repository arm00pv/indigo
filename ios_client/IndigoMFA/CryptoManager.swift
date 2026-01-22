import Foundation
import CryptoKit

class CryptoManager {
    static let shared = CryptoManager()
    private let keyTag = "com.indigomfa.keys.private"

    // 1. Generate / Retrieve Key
    func getPrivateKey() throws -> P256.KeyAgreement.PrivateKey {
        // In real app, store in Keychain. Here we generate ephemeral for demo or load if saved.
        // For simplicity of this snippet, we generate new one. Ideally check Keychain.
        return P256.KeyAgreement.PrivateKey()
    }

    func getPublicKeyPem() throws -> String {
        let privateKey = try getPrivateKey()
        let publicKey = privateKey.publicKey
        let x963 = publicKey.x963Representation
        // Wrap in ASN.1 for SubjectPublicKeyInfo (P-256 OID) if needed by backend,
        // OR backend can accept raw hex if modified.
        // The Python backend expects PEM with SubjectPublicKeyInfo.
        // Swift CryptoKit doesn't natively export PEM.
        // Manual construction of ASN.1 header for P-256:
        let header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        ]
        var keyBytes = header
        keyBytes.append(contentsOf: x963) // x963 starts with 0x04

        let b64 = Data(keyBytes).base64EncodedString()
        return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----"
    }

    // 2. Decrypt ECIES
    func decrypt(encryptedHex: String, privateKey: P256.KeyAgreement.PrivateKey) throws -> String {
        guard let data = Data(hexString: encryptedHex) else { throw NSError(domain: "Hex", code: 0) }

        // Format: [65 bytes Pub][12 bytes IV][Ciphertext + Tag]
        let pubKeyData = data.subdata(in: 0..<65)
        let ivData = data.subdata(in: 65..<77)
        let ciphertextData = data.subdata(in: 77..<data.count)

        // A. ECDH
        let ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: pubKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPub)

        // B. HKDF (RFC 5869)
        // Salt = 32 bytes of zeros
        let salt = Data(count: 32)
        let info = "mfa-protocol-encryption".data(using: .utf8)!

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: 32
        )

        // C. AES-GCM
        let sealedBox = try AES.GCM.SealedBox(combined: ivData + ciphertextData)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)

        guard let otp = String(data: decryptedData, encoding: .utf8) else {
            throw NSError(domain: "UTF8", code: 0)
        }
        return otp
    }
}

extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var ptr = hexString.startIndex
        for _ in 0..<len {
            let end = hexString.index(after: ptr)
            let byteStr = hexString[ptr...end]
            guard let num = UInt8(byteStr, radix: 16) else { return nil }
            data.append(num)
            ptr = hexString.index(after: end)
        }
        self = data
    }
}
