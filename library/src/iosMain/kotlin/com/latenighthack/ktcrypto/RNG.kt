package com.latenighthack.ktcrypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.Security.SecRandomCopyBytes
import platform.Security.kSecRandomDefault

@OptIn(ExperimentalForeignApi::class)
actual suspend fun RNG.randomBytes(bytes: ByteArray): ByteArray {
    bytes.usePinned { bytesPinned ->
        SecRandomCopyBytes(kSecRandomDefault, bytes.size.convert(), bytesPinned.addressOf(0))
    }

    return bytes
}

actual suspend fun RNG.randomBytes(count: Int): ByteArray {
    return randomBytes(ByteArray(count))
}
