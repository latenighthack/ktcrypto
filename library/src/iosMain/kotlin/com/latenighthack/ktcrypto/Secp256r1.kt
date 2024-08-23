@file:Suppress("actual_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package com.latenighthack.ktcrypto

import com.latenighthack.objclibs.ktcrypto.KtCrypto
import kotlinx.cinterop.*
import platform.Foundation.NSData
import platform.Foundation.create
import platform.posix.memcpy

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private val ktCrypto = KtCrypto()

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual val Secp256r1.Companion.ECDH: KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey>
    get() = object : KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> {
        override suspend fun sharedSecret(privateKey: Secp256r1PrivateKey, publicKey: Secp256r1PublicKey): ByteArray {
            return ktCrypto.ecdh(privateKey.internalKey.toNSData(), publicKey.internalKey.toNSData()).toByteArray()
        }
    }

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual class Secp256r1PublicKey(val internalKey: ByteArray) : PublicKey {
    actual companion object {}

    actual override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean {
        return ktCrypto.verify(
            internalKey.toNSData(),
            message.toNSData(),
            signature.toNSData(),
        )
    }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey {
    return Secp256r1PublicKey(ktCrypto.decodePublicKey(encodedKey.toNSData()).toByteArray())
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1PublicKey.encode(): ByteArray {
    return ktCrypto.encodePublicKey(internalKey.toNSData()).toByteArray()
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual class Secp256r1PrivateKey(val internalKey: ByteArray) : PrivateKey {
    actual companion object {}

    actual override suspend fun sign(message: ByteArray): ByteArray {
        return ktCrypto.sign(internalKey.toNSData(), message.toNSData()).toByteArray()
    }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey {
    return Secp256r1PrivateKey(raw)
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1PrivateKey.encode(): ByteArray {
    return ktCrypto.encodePrivateKey(internalKey.toNSData()).toByteArray()
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual class Secp256r1KeyPair(
    actual override val publicKey: Secp256r1PublicKey,
    actual override val privateKey: Secp256r1PrivateKey
) : KeyPair<Secp256r1PublicKey, Secp256r1PrivateKey> {
    actual companion object
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1KeyPair.Companion.generate(): Secp256r1KeyPair {
    val nativePair = ktCrypto.generateKeyPair()

    return Secp256r1KeyPair(
        publicKey = Secp256r1PublicKey((nativePair["publicKey"] as NSData).toByteArray()),
        privateKey = Secp256r1PrivateKey((nativePair["privateKey"] as NSData).toByteArray())
    )
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
actual suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair? {
    return ktCrypto.fromPrivateKey(raw.toNSData())?.let { nativePair ->
        Secp256r1KeyPair(
            publicKey = Secp256r1PublicKey((nativePair["publicKey"] as NSData).toByteArray()),
            privateKey = Secp256r1PrivateKey((nativePair["privateKey"] as NSData).toByteArray())
        )
    }
}

@OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)
private fun ByteArray.toNSData(): NSData {
    return this.usePinned { pinned ->
        if (this.isEmpty()) {
            NSData()
        } else {
            NSData.create(bytes = pinned.addressOf(0), length = this.size.toULong())
        }
    }
}

@OptIn(ExperimentalForeignApi::class)
private fun NSData.toByteArray(): ByteArray {
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
