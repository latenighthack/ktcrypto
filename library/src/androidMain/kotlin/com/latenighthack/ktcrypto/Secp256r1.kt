package com.latenighthack.ktcrypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.*

private val ecKeyFactory = KeyFactory.getInstance("EC")

private val ecdhImplementation = object : KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> {
    override suspend fun sharedSecret(privateKey: Secp256r1PrivateKey, publicKey: Secp256r1PublicKey): ByteArray {
        return javax.crypto.KeyAgreement.getInstance("ECDH")
            .apply {
                init(privateKey.internalKey)
                doPhase(publicKey.internalKey, true)
            }
            .generateSecret()
    }
}

actual val Secp256r1.Companion.ECDH: KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> get() = ecdhImplementation

actual class Secp256r1KeyPair(
    actual override val publicKey: Secp256r1PublicKey,
    actual override val privateKey: Secp256r1PrivateKey
) : KeyPair<Secp256r1PublicKey, Secp256r1PrivateKey> {
    actual companion object
}

actual suspend fun Secp256r1KeyPair.Companion.generate() = KeyPairGenerator.getInstance("EC").let {
    it.initialize(ECGenParameterSpec("secp256r1"))

    lateinit var finalKeyPair: java.security.KeyPair

    while (true) {
        val keyPair = it.generateKeyPair()
        val publicKey = keyPair.public as java.security.interfaces.ECPublicKey
        if (publicKey.w.affineX.toByteArray().size > 32) continue
        if (publicKey.w.affineY.toByteArray().size > 32) continue

        finalKeyPair = keyPair
        break
    }

    Secp256r1KeyPair(
        Secp256r1PublicKey(finalKeyPair.public),
        Secp256r1PrivateKey(finalKeyPair.private)
    )
}

actual suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair? {
    val curve = EllipticCurve(
        ECFieldFp(BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
        BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    )
    val ecSpec = ECParameterSpec(
        curve,
        ECPoint(
            BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CB8C4E3FC26C8D66AF1FB59DFAE2204", 16)
        ),
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        1
    )

    val d = BigInteger(1, raw)
    val privSpec = ECPrivateKeySpec(d, ecSpec)
    val privateKey = ecKeyFactory.generatePrivate(privSpec)

    val keyFactory = KeyFactory.getInstance("EC")
    val publicKey = keyFactory.generatePublic(privSpec) as java.security.interfaces.ECPublicKey

    return Secp256r1KeyPair(
        privateKey = Secp256r1PrivateKey(privateKey),
        publicKey = Secp256r1PublicKey(publicKey)
    )
}

actual class Secp256r1PublicKey(val internalKey: java.security.PublicKey) : PublicKey {
    actual override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean {
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA")
        ecdsaSign.initVerify(internalKey)
        ecdsaSign.update(message)

        val k = signature.size / 2
        val rBytes = BigInteger(1, signature.sliceArray(0 until k)).toByteArray()
        val sBytes = BigInteger(1, signature.sliceArray(k until k * 2)).toByteArray()

        val derSig = ByteArray(2 + (2 + rBytes.size) + (2 + sBytes.size))

        derSig[0] = 0x30
        derSig[1] = (2 + rBytes.size + 2 + sBytes.size).toByte()

        derSig[2] = 0x2
        derSig[3] = rBytes.size.toByte()
        rBytes.copyInto(derSig, 4)

        derSig[4 + rBytes.size] = 0x2
        derSig[4 + rBytes.size + 1] = sBytes.size.toByte()
        sBytes.copyInto(derSig, 4 + rBytes.size + 2)

        return ecdsaSign.verify(derSig)
    }

    actual companion object {}
}

actual suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey {
    val curve = EllipticCurve(
        ECFieldFp(BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
        BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    )
    val ecSpec = ECParameterSpec(
        curve,
        ECPoint(
            BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CB8C4E3FC26C8D66AF1FB59DFAE2204", 16)
        ),
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        1
    )
    val x = BigInteger(1, encodedKey.copyOfRange(1, 1 + 32))
    val y = BigInteger(1, encodedKey.copyOfRange(33, 33 + 32))
    val ecPoint = ECPoint(x, y)

    val publicKey = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ecPoint, ecSpec))
    return Secp256r1PublicKey(publicKey)
}

actual suspend fun Secp256r1PublicKey.encode(): ByteArray {
    val point = (internalKey as java.security.interfaces.ECPublicKey).w
    val buf = ByteArray(33)

    point.affineX.toByteArray().copyInto(buf, 1)
    buf[0] = if (point.affineY.testBit(0)) 3 else 2

    return buf
}

actual class Secp256r1PrivateKey(val internalKey: java.security.PrivateKey) : PrivateKey {
    actual override suspend fun sign(message: ByteArray): ByteArray {
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA")
        ecdsaSign.initSign(internalKey)
        ecdsaSign.update(message)

        val derSig = ecdsaSign.sign()

        val r = BigInteger(1, derSig.sliceArray(4 until 4 + derSig[3]))
        val s = BigInteger(1, derSig.sliceArray(4 + derSig[3] + 2 until derSig.size))

        val rBytes = trimZeros(r.toByteArray())
        val sBytes = trimZeros(s.toByteArray())

        val k = rBytes.size.coerceAtLeast(sBytes.size)
        val result = ByteArray(k shl 1)
        rBytes.copyInto(result, k - rBytes.size)
        sBytes.copyInto(result, result.size - sBytes.size)

        return result
    }

    actual companion object {}
}

actual suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey {
    val curve = EllipticCurve(
        ECFieldFp(BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)),
        BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16),
        BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    )
    val ecSpec = ECParameterSpec(
        curve,
        ECPoint(
            BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16),
            BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162CB8C4E3FC26C8D66AF1FB59DFAE2204", 16)
        ),
        BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
        1
    )

    val d = BigInteger(1, raw)
    val privSpec = ECPrivateKeySpec(d, ecSpec)
    val privateKey = ecKeyFactory.generatePrivate(privSpec)

    return Secp256r1PrivateKey(privateKey)
}

actual suspend fun Secp256r1PrivateKey.encode(): ByteArray {
    val s = (internalKey as java.security.interfaces.ECPrivateKey).s
    val length = (256 + 7) / 8
    val byteArray = s.toByteArray()
    return if (byteArray.size == length) {
        byteArray
    } else if (byteArray.size < length) {
        ByteArray(length).apply {
            System.arraycopy(byteArray, 0, this, length - byteArray.size, byteArray.size)
        }
    } else {
        byteArray.copyOfRange(byteArray.size - length, byteArray.size)
    }
}

private fun trimZeros(b: ByteArray): ByteArray {
    var i = 0
    while ((i < b.size - 1) && b[i] == 0.toByte()) {
        i++
    }
    return b.sliceArray(i until b.size)
}
