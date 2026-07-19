@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package com.latenighthack.ktcrypto

import com.latenighthack.objclibs.ktcrypto.KtCrypto
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private val ktCrypto = KtCrypto()

actual suspend fun AESSymmetricKey.Companion.decodeKey(encodedKey: ByteArray) = AESSymmetricKey(encodedKey)

actual suspend fun AESSymmetricKey.encodePublic() = internalKey

actual suspend fun AES.Companion.generateKey(bits: Int): AESSymmetricKey =
    AESSymmetricKey(RNG.randomBytes(bits / 8))

actual class AESSymmetricKey(val internalKey: ByteArray) : SymmetricKey {
    actual companion object
}

interface GCMProvider {
    fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray
    fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray
}

var _aesGCMProvider: GCMProvider? = null

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual open class InternalGCM : Cipher<AESSymmetricKey> {
    actual override suspend fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray {
        _aesGCMProvider?.let { return it.encrypt(key, clearText) }

        return ktCrypto.gcmEncrypt(key.internalKey.toNSData(), clearText.toNSData()).toByteArray()
    }

    actual override suspend fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray {
        _aesGCMProvider?.let { return it.decrypt(key, cipherText) }

        return ktCrypto.gcmDecrypt(key.internalKey.toNSData(), cipherText.toNSData())?.toByteArray()
            ?: throw Exception("AES-GCM decryption failed")
    }
}
