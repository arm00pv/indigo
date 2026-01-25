package com.indigomfa.android

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    private var baseUrl = "http://10.0.2.2:5000" // Default, overridden by Config
    private var tenantId = "default"
    private var userId = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Generate Key if missing
        try {
            CryptoManager.generateKeyPair()
        } catch (e: Exception) {
            // Already exists or error
        }

        findViewById<Button>(R.id.btnConfig).setOnClickListener {
            val input = findViewById<EditText>(R.id.etSmartCode).text.toString()
            if (input.isNotEmpty()) {
                parseAndRegister(input)
            }
        }

        findViewById<Button>(R.id.btnAuth).setOnClickListener {
            authenticate()
        }
    }

    private fun parseAndRegister(jsonString: String) {
        try {
            // Smart Code might be Base64 encoded or raw JSON
            val jsonStr = if (!jsonString.trim().startsWith("{")) {
                String(android.util.Base64.decode(jsonString, android.util.Base64.DEFAULT))
            } else {
                jsonString
            }

            val config = JSONObject(jsonStr)
            // Parse Config
            // Expected: {"url": "...", "tenant_id": "...", "user_id": "..."}

            val rawUrl = config.optString("url", baseUrl)
            // Fix localhost for Emulator if needed
            baseUrl = rawUrl.replace("localhost", "10.0.2.2").replace("127.0.0.1", "10.0.2.2")

            tenantId = config.optString("tenant_id", "default")
            userId = config.optString("user_id", "")

            updateStatus("Configured: $userId @ $tenantId. Registering...")
            register()

        } catch (e: Exception) {
            updateStatus("Config Error: ${e.message}")
        }
    }

    private fun updateStatus(msg: String) {
        runOnUiThread {
            findViewById<TextView>(R.id.tvStatus).text = msg
        }
    }

    private fun register() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val pubKey = CryptoManager.getPublicKeyPem()
                // Convert PEM string to Hex for backend
                val hex = pubKey.toByteArray().joinToString("") { "%02x".format(it) }

                val json = JSONObject()
                json.put("user_id", userId)
                json.put("public_key_pem_hex", hex)
                json.put("push_endpoint", "")

                val resp = post("$baseUrl/register", json.toString())

                withContext(Dispatchers.Main) {
                    updateStatus("Registration Success: $userId")
                    Toast.makeText(this@MainActivity, "Registered!", Toast.LENGTH_SHORT).show()
                    findViewById<Button>(R.id.btnAuth).isEnabled = true
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    updateStatus("Reg Error: ${e.message}")
                    Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun authenticate() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // 1. Get Challenge
                val json = JSONObject()
                json.put("user_id", userId)
                val resp = post("$baseUrl/auth/challenge", json.toString())
                val respJson = JSONObject(resp)
                val encryptedHex = respJson.getString("encrypted_challenge_hex")

                // 2. Decrypt
                val encryptedBytes = hexStringToByteArray(encryptedHex)
                val otp = CryptoManager.decrypt(encryptedBytes)

                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Decrypted OTP: $otp", Toast.LENGTH_SHORT).show()
                }

                // 3. Verify
                // Note: Implement Duress Logic here by modifying OTP if Duress PIN entered
                val verifyJson = JSONObject()
                verifyJson.put("user_id", userId)
                verifyJson.put("otp", otp)

                val verifyResp = post("$baseUrl/auth/verify", verifyJson.toString())

                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Success: $verifyResp", Toast.LENGTH_LONG).show()
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Auth Failed: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun post(urlStr: String, jsonBody: String): String {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("X-Tenant-ID", tenantId)
        conn.doOutput = true

        conn.outputStream.use { it.write(jsonBody.toByteArray()) }

        val code = conn.responseCode
        if (code >= 400) {
            throw Exception("HTTP $code")
        }
        return conn.inputStream.bufferedReader().readText()
    }

    private fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4) + Character.digit(s[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}
