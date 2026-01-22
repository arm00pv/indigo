import SwiftUI

struct ContentView: View {
    @State private var status: String = "Ready"
    @State private var userId: String = "ios_user"

    // Backend URL
    let baseUrl = "http://localhost:5000"
    let tenantId = "default"

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "shield.fill")
                .imageScale(.large)
                .foregroundColor(.accentColor)
            Text("Indigo MFA").font(.title)

            TextField("User ID", text: $userId)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()

            Button("Register Device") {
                register()
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(8)

            Button("Authenticate") {
                authenticate()
            }
            .padding()
            .background(Color.green)
            .foregroundColor(.white)
            .cornerRadius(8)

            Text(status)
                .padding()
                .multilineTextAlignment(.center)
        }
    }

    func register() {
        guard let pubKey = try? CryptoManager.shared.getPublicKeyPem() else { return }

        // Convert to Hex
        let hex = pubKey.data(using: .utf8)?.map { String(format: "%02x", $0) }.joined() ?? ""

        let url = URL(string: "\(baseUrl)/register")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")

        let body: [String: String] = [
            "user_id": userId,
            "public_key_pem_hex": hex,
            "push_endpoint": ""
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { data, resp, err in
            DispatchQueue.main.async {
                if let _ = err { self.status = "Network Error"; return }
                self.status = "Registration Request Sent"
            }
        }.resume()
    }

    func authenticate() {
        // 1. Get Challenge
        let url = URL(string: "\(baseUrl)/auth/challenge")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")

        let body = ["user_id": userId]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { data, resp, err in
            guard let data = data, let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let encryptedHex = json["encrypted_challenge_hex"] as? String else {
                DispatchQueue.main.async { self.status = "Failed to get challenge" }
                return
            }

            // 2. Decrypt
            do {
                let privKey = try CryptoManager.shared.getPrivateKey()
                let otp = try CryptoManager.shared.decrypt(encryptedHex: encryptedHex, privateKey: privKey)

                DispatchQueue.main.async { self.status = "Decrypted OTP: \(otp). Verifying..." }

                // 3. Verify
                self.verify(otp: otp)

            } catch {
                DispatchQueue.main.async { self.status = "Decryption Failed: \(error)" }
            }
        }.resume()
    }

    func verify(otp: String) {
        let url = URL(string: "\(baseUrl)/auth/verify")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")

        let body = ["user_id": userId, "otp": otp]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { data, resp, err in
            DispatchQueue.main.async {
                if let _ = err { self.status = "Verify Error"; return }
                self.status = "Auth Successful!"
            }
        }.resume()
    }
}
