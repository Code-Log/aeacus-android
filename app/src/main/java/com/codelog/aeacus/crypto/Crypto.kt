package com.codelog.aeacus.crypto

import com.codelog.aeacus.api.Payload
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.openssl.PEMParser
import org.spongycastle.openssl.PKCS8Generator
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter
import org.spongycastle.openssl.jcajce.JcaPKCS8Generator
import org.spongycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder
import org.spongycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
import org.spongycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder
import org.spongycastle.util.encoders.Hex
import org.spongycastle.util.io.pem.PemObject
import org.spongycastle.util.io.pem.PemWriter
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter
import java.io.StringReader
import java.security.*
import java.util.*
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class Token(val token: String, val signature: String)

object Crypto {
    init {
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    private fun decryptPrivateKey(secretKey: String, vaultKey: String): PrivateKey {
        val parser = PEMParser(StringReader(secretKey))
        val pemKeyPair: PKCS8EncryptedPrivateKeyInfo = parser.readObject() as PKCS8EncryptedPrivateKeyInfo
        val decryptor = JcePKCSPBEInputDecryptorProviderBuilder().build(vaultKey.toCharArray())
        val converter = JcaPEMKeyConverter()
        val pki = pemKeyPair.decryptPrivateKeyInfo(decryptor)
        return converter.getPrivateKey(pki)
    }

    fun generateToken(secretKey: String, vaultKey: String): Token {
        val rand = SecureRandom()
        val tokenBytes = ByteArray(32) { 0 }
        rand.nextBytes(tokenBytes)
        val tokenString = Hex.toHexString(tokenBytes)
        val signatureString = signString(tokenString, secretKey, vaultKey)

        return Token(tokenString, signatureString)
    }

    fun signPayload(payload: Payload, secretKey: String, vaultKey: String): String {
        return signString(payload.serialize().toString(), secretKey, vaultKey)
    }

    fun signString(msg: String, secretKey: String, vaultKey: String): String {
        val msgBytes = msg.encodeToByteArray()
        val privateKey = decryptPrivateKey(secretKey, vaultKey)
        val sign = Signature.getInstance("SHA256withRSA").apply {
            initSign(privateKey)
            update(msgBytes)
        }

        val sigBytes = sign.sign()
        return Hex.toHexString(sigBytes);
    }

    fun generateKeyPair(vaultKey: String): Pair<String, String> {
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(4096, SecureRandom(SecureRandom.getSeed(32)))
        val keyPair = gen.generateKeyPair()
        val builder = JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
        builder.setIterationCount(10000)
        builder.setPasssword(vaultKey.toCharArray())
        builder.setProvider(BouncyCastleProvider())
        val encryptor = builder.build();
        val pemGenerator = JcaPKCS8Generator(keyPair.private, encryptor)
        var byteStream = ByteArrayOutputStream()
        var pemWriter = PemWriter(OutputStreamWriter(byteStream))
        pemWriter.writeObject(pemGenerator)
        pemWriter.close()


        val pemPublicKey = PemObject("PUBLIC KEY", keyPair.public.encoded)

        val skString = byteStream.toString()

        byteStream = ByteArrayOutputStream()
        pemWriter = PemWriter (OutputStreamWriter(byteStream))
        pemWriter.writeObject(pemPublicKey)
        pemWriter.close()

        val pkString = byteStream.toString()

        return Pair(pkString, skString)
    }

    fun getSaltBytes(saltLength: Int): ByteArray {
        val rand = SecureRandom(SecureRandom.getSeed(32))
        val result = ByteArray(saltLength)
        rand.nextBytes(result)
        return result
    }

    fun hmacSha256(key: String, msg: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        val sk = SecretKeySpec(Base64.getDecoder().decode(key), mac.algorithm)
        mac.init(sk)
        val resultBytes = mac.doFinal(msg.encodeToByteArray())
        return Hex.toHexString(resultBytes)
    }

    fun pbkdf2Sha256(secret: String, salt: ByteArray, iterations: Int, keyLength: Int): String {
        val spec = PBEKeySpec(secret.toCharArray(), salt, iterations, keyLength)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val key = factory.generateSecret(spec)
        return Base64.getEncoder().encodeToString(key.encoded)
    }
}