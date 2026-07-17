package com.latenighthack.ktcrypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.convert
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH

@OptIn(ExperimentalForeignApi::class)
actual suspend fun SHA256.digest(bytes: ByteArray): ByteArray {
    val digest = UByteArray(CC_SHA256_DIGEST_LENGTH)

    // addressOf(0) is out of bounds for a zero-length array on Kotlin/Native, so for empty input
    // pin a 1-byte scratch for a valid base pointer and still hash the real (zero) length — this
    // yields the correct SHA-256 of the empty string rather than crashing.
    val input = if (bytes.isEmpty()) ByteArray(1) else bytes

    input.usePinned { inputPinned ->
        digest.usePinned { digestPinned ->
            CC_SHA256(inputPinned.addressOf(0), bytes.size.convert(), digestPinned.addressOf(0))
        }
    }

    return digest.asByteArray()
}
