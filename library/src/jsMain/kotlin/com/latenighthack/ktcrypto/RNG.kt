package com.latenighthack.ktcrypto

import org.khronos.webgl.Int8Array

actual suspend fun RNG.randomBytes(bytes: ByteArray): ByteArray {
    js(
        """
    window.crypto.getRandomValues(bytes);
    """
    )

    return bytes
}

actual suspend fun RNG.randomBytes(count: Int): ByteArray {
    val array = Int8Array(count)

    js(
        """
    window.crypto.getRandomValues(array);
    """
    )

    return array.unsafeCast<ByteArray>()
}
