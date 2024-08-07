package com.latenighthack.ktcrypto

import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array
import kotlin.js.Promise

actual suspend fun AESSymmetricKey.Companion.decodeKey(encodedKey: ByteArray) = AESSymmetricKey(encodedKey)

actual suspend fun AESSymmetricKey.encodePublic(): ByteArray = internalKey

actual suspend fun AES.Companion.generateKey(bits: Int): AESSymmetricKey {
    val cryptoKey = (js(
        """
        crypto.subtle.generateKey({ "name": "AES-GCM", "length": 128}, true, ["encrypt", "decrypt"])        
        """
    ) as Promise<*>).await()

    return AESSymmetricKey(cryptoKey.asDynamic())
}

actual class AESSymmetricKey(val internalKey: dynamic /* CryptoKey */) : SymmetricKey {
    actual companion object
}

actual open class InternalGCM : Cipher<AESSymmetricKey> {
    actual override suspend fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray {
        var iv: ByteArray? = null
        val arrayBufferData = (js(
            """
        iv = window.crypto.getRandomValues(new Int8Array(12));
        
        window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv: iv
        }, key.internalKey, clearText);
        """
        ) as Promise<*>).await() as ArrayBuffer

        val cipherText = Int8Array(arrayBufferData).unsafeCast<ByteArray>()

        return byteArrayOf(*iv!!, *cipherText)
    }

    actual override suspend fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray {
        val arrayBufferData = (js(
            """
        window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: cipherText.subarray(0, 12)
        }, key.internalKey, cipherText.subarray(12));
        """
        ) as Promise<*>).await() as ArrayBuffer

        return Int8Array(arrayBufferData).unsafeCast<ByteArray>()
    }
}
