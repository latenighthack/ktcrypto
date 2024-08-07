package com.latenighthack.ktcrypto

import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array
import kotlin.js.Promise

actual suspend fun SHA256.digest(bytes: ByteArray): ByteArray {
    val digestBuffer = (js(
        """
    crypto.subtle.digest("SHA-256", bytes);
    """
    ) as Promise<ArrayBuffer>).await()

    return Int8Array(digestBuffer).unsafeCast<ByteArray>()
}
