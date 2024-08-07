@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package com.latenighthack.ktcrypto

actual suspend fun AESSymmetricKey.Companion.decodeKey(encodedKey: ByteArray) = AESSymmetricKey(encodedKey)

actual suspend fun AESSymmetricKey.encodePublic() = internalKey

actual suspend fun AES.Companion.generateKey(bits: Int): AESSymmetricKey = TODO()

actual class AESSymmetricKey(val internalKey: ByteArray) : SymmetricKey {
    actual companion object
}

interface GCMProvider {
    fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray
    fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray
}

var _aesGCMProvider: GCMProvider? = null;

actual open class InternalGCM : Cipher<AESSymmetricKey> {
    actual override suspend fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray {
        return _aesGCMProvider!!.encrypt(key, clearText)
    }

    actual override suspend fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray {
        return _aesGCMProvider!!.decrypt(key, cipherText)
    }
}
