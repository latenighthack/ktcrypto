package com.latenighthack.ktcrypto

import kotlinx.cinterop.*
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
internal fun ByteArray.toNSData(): NSData {
    return this.usePinned { pinned ->
        if (this.isEmpty()) {
            NSData()
        } else {
            NSData.create(bytes = pinned.addressOf(0), length = this.size.toULong())
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
internal fun NSData.toByteArray(): ByteArray {
    if (this.length.toInt() == 0) {
        return byteArrayOf()
    }

    val byteArray = ByteArray(this.length.toInt())
    memScoped {
        val buffer = byteArray.refTo(0).getPointer(this)

        memcpy(buffer, this@toByteArray.bytes, this@toByteArray.length)
    }
    return byteArray
}
