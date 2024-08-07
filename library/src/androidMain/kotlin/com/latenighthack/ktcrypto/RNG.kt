package com.latenighthack.ktcrypto

import java.security.SecureRandom

private fun secureRandom(): SecureRandom {
    return SecureRandom.getInstanceStrong()
}

actual suspend fun RNG.randomBytes(bytes: ByteArray): ByteArray {
    secureRandom().nextBytes(bytes)

    return bytes
}

actual suspend fun RNG.randomBytes(count: Int): ByteArray {
    return ByteArray(count).apply {
        randomBytes(this)
    }
}
