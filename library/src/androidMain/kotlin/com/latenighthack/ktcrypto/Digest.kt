package com.latenighthack.ktcrypto

import java.security.MessageDigest

actual suspend fun SHA256.digest(bytes: ByteArray): ByteArray {
    return MessageDigest.getInstance("SHA-256").let {
        it.reset()
        it.digest(bytes)
    }
}
