package com.codelog.aeacus.api

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.codelog.aeacus.MainActivity
import com.codelog.aeacus.crypto.Crypto
import com.codelog.aeacus.crypto.Token
import com.codelog.aeacus.util.FileUtils
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

object UserContext {
    var currentUser: User? = null

    fun createFromCredentials(username: String, password: String, cb: (String?) -> Unit) {
        var req = APIRequest("getSalt", false, "uname")
        req.sendAsync({ res ->
            if (res.get("status").asString == "error") {
                cb(res.get("message").asString)
                return@sendAsync
            }

            val salt = Base64.getDecoder().decode(res.get("salt").asString)
            val vaultKey = Crypto.pbkdf2Sha256(username + password,
                salt, 310000, 256)

            val authKey = Crypto.pbkdf2Sha256(vaultKey + password, salt, 310000, 128)

            req = APIRequest("getUser", false, "uname", "authKey")

            req.sendAsync({ res ->
                if (res.get("status").asString == "error") {
                    cb(res.get("message").asString)
                    return@sendAsync
                }

                val userJson = res.getAsJsonObject("user")
                val userHmac = userJson.get("hmac").asString
                val publicKey = userJson.get("publicKey").asString
                val secretKey = userJson.get("secretKey").asString

                val saltStr = Base64.getEncoder().encodeToString(salt)

                val hmac = Crypto.hmacSha256(vaultKey, publicKey + secretKey + saltStr)

                if (hmac != userHmac) {
                    cb("Server hmac did not match calculated hmac. Someone may be screwing with us!")
                    return@sendAsync
                }

                currentUser = User(
                    username,
                    userJson.get("publicKey").asString,
                    userJson.get("secretKey").asString,
                    vaultKey
                )
                cb(null)
            }, username, authKey)
        }, username)
    }

    fun registerNewUser(username: String, password: String, cb: (String?) -> Unit) {
        val salt = Crypto.getSaltBytes(16)
        val vaultKey = Crypto.pbkdf2Sha256(username + password, salt, 310000, 256)
        val authKey = Crypto.pbkdf2Sha256(vaultKey + password, salt, 310000, 128)

        val keyPair = Crypto.generateKeyPair(vaultKey)

        val hmac = Crypto.hmacSha256(vaultKey, keyPair.first + keyPair.second + Base64.getEncoder().encodeToString(salt))

        val userJson = JsonObject()
        userJson.addProperty("authKey", authKey)
        userJson.addProperty("username", username)

        System.out.printf("Challenge object: %s\n", userJson.toString())

        val sig = Crypto.signString(userJson.toString().replace("\\/", "/"), keyPair.second, vaultKey)
        val req = APIRequest("register",
            false,
            "uname",
            "authKey",
            "publicKey",
            "secretKey",
            "salt",
            "challengeSignature",
            "hmac"
        )

        req.sendAsync({ res ->
                if (res.get("status").asString == "error") {
                    cb(res.get("message").asString)
                }
                cb(null)
        }, username, authKey, keyPair.first, keyPair.second,
            Base64.getEncoder().encodeToString(salt), sig, hmac)
    }

    fun save() {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            "main",
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build()
        gen.init(spec)
        val key = gen.generateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv

        val encrypted = cipher.doFinal(currentUser?.serialize().toString().toByteArray(Charsets.UTF_8))

        FileUtils.writeBinary(File(MainActivity.context.filesDir, "user.bin"), encrypted)
        FileUtils.writeBinary(File(MainActivity.context.filesDir, "iv.bin"), iv)
    }

    fun recall(): User? {
        if (!Files.exists(File(MainActivity.context.filesDir, "user.bin").toPath()))
            return null

        val iv = FileUtils.readBinary(File(MainActivity.context.filesDir, "iv.bin"))
        val encrypted = FileUtils.readBinary(File(MainActivity.context.filesDir, "user.bin"))

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val keyEntry = keyStore.getEntry("main", null) as KeyStore.SecretKeyEntry
        val key = keyEntry.secretKey

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val decrypted = cipher.doFinal(encrypted)
        val json = JsonParser.parseString(decrypted.toString(Charsets.UTF_8)).asJsonObject

        currentUser = User.fromJSON(json)
        return currentUser
    }

    fun sendMessage(msg: Message, cb: (String?) -> Unit) {
        val req = APIRequest("pushMessage", true, "message")
        req.sendAsync({ res ->
            if (res.get("status").asString == "error") {
                cb(res.get("message").asString)
                return@sendAsync
            }
            cb(null)
        }, msg.serialize())
    }
}

class User (
    val username: String,
    private val publicKey: String,
    val secretKey: String,
    val vaultKey: String
) {
    companion object {
        fun fromJSON(json: JsonObject): User {
            val username = json.get("username").asString
            val publicKey = json.get("publicKey").asString
            val secretKey = json.get("secretKey").asString
            val vaultKey = json.get("vaultKey").asString
            return User(username, publicKey, secretKey, vaultKey)
        }
    }

    val token: Token
    get() {
        return Crypto.generateToken(secretKey, vaultKey)
    }

    fun serialize(): JsonObject {
        val result = JsonObject()
        result.addProperty("username", username)
        result.addProperty("publicKey", publicKey)
        result.addProperty("secretKey", secretKey)
        result.addProperty("vaultKey", vaultKey)
        return result
    }
}