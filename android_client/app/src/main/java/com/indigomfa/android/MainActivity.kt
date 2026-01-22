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

    private val baseUrl = "http://10.0.2.2:5000" // Android Emulator localhost
    private val tenantId = "default"
    private var userId = "test_user" // Hardcoded or input

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Generate Key if missing
        try {
            CryptoManager.generateKeyPair()
        } catch (e: Exception) {
            // Already exists or error
        }

        findViewById<Button>(R.id.btnRegister).setOnClickListener {
            register()
        }

        findViewById<Button>(R.id.btnAuth).setOnClickListener {
            authenticate()
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
                    Toast.makeText(this@MainActivity, "Registered: $resp", Toast.LENGTH_LONG).show()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
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
