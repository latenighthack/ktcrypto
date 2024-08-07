@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package com.latenighthack.ktcrypto

interface Secp256r1Provider {
    fun generateKeyPair(): ByteArray
    fun fromPrivateKey(raw: ByteArray): ByteArray
    fun fromPublicKey(encoded: ByteArray): ByteArray
    fun encodePublic(key: ByteArray): ByteArray

    fun sharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray
    fun verify(publicKey: ByteArray, messageDigest: ByteArray, signature: ByteArray): Boolean
    fun sign(privateKey: ByteArray, messageDigest: ByteArray): ByteArray
}

var _secp256r1Provider: Secp256r1Provider? = null

private object ecdhImplementation : KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> {
    override suspend fun sharedSecret(privateKey: Secp256r1PrivateKey, publicKey: Secp256r1PublicKey): ByteArray =
        _secp256r1Provider!!.sharedSecret(
            privateKey.internalKey,
            publicKey.internalKey
        )
}

actual val Secp256r1.Companion.ECDH: KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> get() = ecdhImplementation

actual class Secp256r1KeyPair(
    actual override val publicKey: Secp256r1PublicKey,
    actual override val privateKey: Secp256r1PrivateKey
) : KeyPair<Secp256r1PublicKey, Secp256r1PrivateKey> {
    actual companion object
}

actual suspend fun Secp256r1KeyPair.Companion.generate(): Secp256r1KeyPair =
    _secp256r1Provider!!.generateKeyPair().let { mergedBytes ->
        Secp256r1KeyPair(
            Secp256r1PublicKey(mergedBytes.copyOfRange(32, mergedBytes.size)),
            Secp256r1PrivateKey(mergedBytes.copyOfRange(0, 32))
        )
    }

actual suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair? {
    val mergedBytes = _secp256r1Provider!!.fromPrivateKey(raw)
    if (mergedBytes.isEmpty()) {
        return null
    }

    return Secp256r1KeyPair(
        Secp256r1PublicKey(mergedBytes.copyOfRange(32, mergedBytes.size)),
        Secp256r1PrivateKey(mergedBytes.copyOfRange(0, 32))
    )
}

actual class Secp256r1PublicKey(val internalKey: ByteArray) : PublicKey {
    actual override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean {
        return _secp256r1Provider!!.verify(internalKey, message, signature)
    }

    actual companion object {}
}

actual suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey = Secp256r1PublicKey(
    _secp256r1Provider!!.fromPublicKey(encodedKey)
)

actual suspend fun Secp256r1PublicKey.encode(): ByteArray = _secp256r1Provider!!.encodePublic(internalKey)

actual class Secp256r1PrivateKey(val internalKey: ByteArray) : PrivateKey {
    actual override suspend fun sign(message: ByteArray): ByteArray {
        return _secp256r1Provider!!.sign(internalKey, message)
    }

    actual companion object {}
}

actual suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey {
    val merged = _secp256r1Provider!!.fromPrivateKey(raw)
    return Secp256r1PrivateKey(merged.copyOfRange(0, 32))
}

actual suspend fun Secp256r1PrivateKey.encode(): ByteArray = this.internalKey
