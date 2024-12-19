package com.latenighthack.ktcrypto

import java.security.SecureRandom
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual suspend fun AESSymmetricKey.Companion.decodeKey(encodedKey: ByteArray) = AESSymmetricKey(encodedKey)

actual suspend fun AESSymmetricKey.encodePublic() = internalKey

actual suspend fun AES.Companion.generateKey(bits: Int) =
    ByteArray(bits / 8).let { bytes ->
        SecureRandom.getInstanceStrong().nextBytes(bytes)

        AESSymmetricKey(bytes)
    }

actual class AESSymmetricKey(val internalKey: ByteArray) : SymmetricKey {
    actual companion object
}

actual open class InternalGCM : Cipher<AESSymmetricKey> {
    actual override suspend fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray =
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").let { cipher ->
            val keySpec = SecretKeySpec(key.internalKey, "AES")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)

            val cipherText = cipher.doFinal(clearText)

            byteArrayOf(*cipher.iv, *cipherText)
        }

    actual override suspend fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray =
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").let { cipher ->
            val keySpec = SecretKeySpec(key.internalKey, "AES")
            val params = GCMParameterSpec(128, cipherText, 0, 12)

            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, params)
            cipher.doFinal(cipherText, 12, cipherText.size - 12)
        }
}
