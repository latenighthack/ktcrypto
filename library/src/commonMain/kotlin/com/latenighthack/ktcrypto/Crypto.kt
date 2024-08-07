@file:Suppress("EXPECT_ACTUAL_CLASSIFIERS_ARE_IN_BETA_WARNING")

package com.latenighthack.ktcrypto

interface Digest

object SHA256 : Digest

expect suspend fun SHA256.digest(bytes: ByteArray): ByteArray

object RNG

expect suspend fun RNG.randomBytes(bytes: ByteArray): ByteArray
expect suspend fun RNG.randomBytes(count: Int): ByteArray

interface SymmetricKey
interface Cipher<Key : SymmetricKey> {
    suspend fun encrypt(key: Key, clearText: ByteArray): ByteArray
    suspend fun decrypt(key: Key, cipherText: ByteArray): ByteArray
}

expect class AESSymmetricKey : SymmetricKey {
    companion object {}
}

interface PublicKey {
    suspend fun verify(message: ByteArray, signature: ByteArray): Boolean
}

interface PrivateKey {
    suspend fun sign(message: ByteArray): ByteArray
}

interface KeyPair<PublicType : PublicKey, PrivateType : PrivateKey> {
    val publicKey: PublicType
    val privateKey: PrivateType
}

interface KeyAgreement<PublicKeyType : PublicKey, PrivateKeyType : PrivateKey> {
    suspend fun sharedSecret(privateKey: PrivateKeyType, publicKey: PublicKeyType): ByteArray
}

class AES {
    object GCM : InternalGCM()

    companion object {}
}

expect open class InternalGCM() : Cipher<AESSymmetricKey> {
    override suspend fun decrypt(key: AESSymmetricKey, cipherText: ByteArray): ByteArray
    override suspend fun encrypt(key: AESSymmetricKey, clearText: ByteArray): ByteArray
}

expect suspend fun AES.Companion.generateKey(bits: Int = 256): AESSymmetricKey

expect suspend fun AESSymmetricKey.Companion.decodeKey(encodedKey: ByteArray): AESSymmetricKey
expect suspend fun AESSymmetricKey.encodePublic(): ByteArray

class Secp256r1 {
    companion object {}
}

expect val Secp256r1.Companion.ECDH: KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey>

expect class Secp256r1PublicKey : PublicKey {
    companion object {}

    override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean
}

expect suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey
expect suspend fun Secp256r1PublicKey.encode(): ByteArray

expect class Secp256r1PrivateKey : PrivateKey {
    companion object {}

    override suspend fun sign(message: ByteArray): ByteArray
}

expect suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey
expect suspend fun Secp256r1PrivateKey.encode(): ByteArray

expect class Secp256r1KeyPair : KeyPair<Secp256r1PublicKey, Secp256r1PrivateKey> {
    companion object {}

    override val publicKey: Secp256r1PublicKey
    override val privateKey: Secp256r1PrivateKey
}

expect suspend fun Secp256r1KeyPair.Companion.generate(): Secp256r1KeyPair
expect suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair?

suspend fun Secp256r1KeyPair.derive(seq: ULong): Pair<Secp256r1KeyPair, ULong> {
    val rootSeed = this.privateKey.encode()
    val buf = ByteArray(rootSeed.size + 8)
    rootSeed.copyInto(buf)

    var usedSeq = seq

    while (true) {
        for (i in 1..8) {
            buf[buf.size - i] = (usedSeq shr (i - 1) * 8 and 255u).toByte()
        }

        val privateKey = SHA256.digest(buf)
        val derived = Secp256r1KeyPair.fromPrivateKey(privateKey)
        if (derived != null) {
            return Pair(derived, usedSeq)
        }
    }
}

private val pkcs8Prefix = listOf(
    48,
    65,
    2,
    1,
    0,
    48,
    19,
    6,
    7,
    42,
    134,
    72,
    206,
    61,
    2,
    1,
    6,
    8,
    42,
    134,
    72,
    206,
    61,
    3,
    1,
    7,
    4,
    39,
    48,
    37,
    2,
    1,
    1,
    4,
    32
)
    .map { it.toByte() }
    .toByteArray()

fun encodePKCS8Private(rawKey: ByteArray): ByteArray {
    if (rawKey.size != 32) {
        throw Exception("invalid key size")
    }

    val buf = ByteArray(pkcs8Prefix.size + rawKey.size)
    pkcs8Prefix.copyInto(buf)
    rawKey.copyInto(buf, pkcs8Prefix.size)
    return buf
}
