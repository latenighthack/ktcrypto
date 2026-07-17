package com.latenighthack.ktcrypto

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.custom.sec.SecP256R1FieldElement
import org.bouncycastle.util.BigIntegers
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

private val bcProvider = BouncyCastleProvider()
private val ecKeyFactory = KeyFactory.getInstance("EC", bcProvider)

private val ecdhImplementation = object : KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> {
    override suspend fun sharedSecret(privateKey: Secp256r1PrivateKey, publicKey: Secp256r1PublicKey): ByteArray {
        return javax.crypto.KeyAgreement.getInstance("ECDH", bcProvider)
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

actual suspend fun Secp256r1KeyPair.Companion.generate() = KeyPairGenerator.getInstance("EC", bcProvider).let {
    it.initialize(ECGenParameterSpec("secp256r1"))

    lateinit var finalKeyPair: java.security.KeyPair

    while (true) {
        val keyPair = it.generateKeyPair()
        val publicKey = (keyPair.public as ECPublicKey)
        if (publicKey.q.affineXCoord.toBigInteger().toByteArray().size > 32) continue
        if (publicKey.q.affineYCoord.toBigInteger().toByteArray().size > 32) continue

        finalKeyPair = keyPair
        break
    }

    Secp256r1KeyPair(
        Secp256r1PublicKey(finalKeyPair.public),
        Secp256r1PrivateKey(finalKeyPair.private)
    )
}


actual suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair? {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")
    val domainParams = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)

    val d = BigInteger(1, raw)
    val privSpec = ECPrivateKeySpec(d, domainParams)
    val pubSpec = ECPublicKeySpec(domainParams.g.multiply(d), domainParams)
    val privateKey = ecKeyFactory.generatePrivate(privSpec)
    val pubKey = ecKeyFactory.generatePublic(pubSpec)

    return Secp256r1KeyPair(
        privateKey = Secp256r1PrivateKey(privateKey),
        publicKey = Secp256r1PublicKey(pubKey)
    )
}

actual class Secp256r1PublicKey(val internalKey: java.security.PublicKey) : PublicKey {
    actual override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean {
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA", bcProvider)
        ecdsaSign.initVerify(internalKey)
        ecdsaSign.update(message)

        val k = signature.size/2
        val rBytes = BigInteger(1, signature.sliceArray(0 until k)).toByteArray()
        val sBytes = BigInteger(1, signature.sliceArray( k until k*2)).toByteArray()

        // 2 byte header, 2 byes tag+len per field
        val derSig = ByteArray(2 + (2 + rBytes.size) + (2 + sBytes.size))

        derSig[0] = 0x30
        derSig[1] = (2 + rBytes.size + 2 + sBytes.size).toByte()

        derSig[2] = 0x2
        derSig[3] = rBytes.size.toByte()
        rBytes.copyInto(derSig, 4)

        derSig[4+rBytes.size] = 0x2
        derSig[4+rBytes.size+1] = sBytes.size.toByte()
        sBytes.copyInto(derSig,  4 + rBytes.size + 2)

        return  ecdsaSign.verify(derSig)
    }

    actual companion object
}

actual suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")
    val pub = params.curve.decodePoint(encodedKey)
    return Secp256r1PublicKey(ecKeyFactory.generatePublic(ECPublicKeySpec(pub, params)))
}

actual suspend fun Secp256r1PublicKey.encode(): ByteArray {
    val point = (internalKey as ECPublicKey).q
    val buf = ByteArray(33)

    point.xCoord.encoded.copyInto(buf, 1)
    buf[0] = if (point.yCoord.testBitZero()) 3 else 2

    return buf
}

actual class Secp256r1PrivateKey(val internalKey: java.security.PrivateKey) : PrivateKey {
    actual override suspend fun sign(message: ByteArray): ByteArray {
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA", bcProvider)
        ecdsaSign.initSign(internalKey)
        ecdsaSign.update(message)
        // BouncyCastle emits a DER-encoded signature; every ktcrypto consumer (and `verify` above)
        // expects a fixed-width 64-byte raw r‖s — the same form iOS/JS emit natively.
        return derToRawSignature(ecdsaSign.sign())
    }

    actual companion object
}

actual suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey {
    val params = ECNamedCurveTable.getParameterSpec("secp256r1")
    val domainParams = ECParameterSpec(params.curve, params.g, params.n, params.h, params.seed)

    val d = BigInteger(1, raw)
    val privSpec = ECPrivateKeySpec(d, domainParams)
    val privateKey = ecKeyFactory.generatePrivate(privSpec)

    return Secp256r1PrivateKey(privateKey)
}

actual suspend fun Secp256r1PrivateKey.encode(): ByteArray {
    val length = (SecP256R1FieldElement.Q.bitLength() + 7) / 8
    return BigIntegers.asUnsignedByteArray(length, (internalKey as ECPrivateKey).d)
}

/**
 * Converts a DER-encoded ECDSA signature to the canonical fixed-width 64-byte raw r‖s that
 * ktcrypto's `verify` (and the iOS/JS platforms) use.
 */
private fun derToRawSignature(der: ByteArray): ByteArray {
    var offset = 0
    require(der.getOrNull(offset++) == 0x30.toByte()) { "invalid DER signature header" }
    offset++ // sequence length — always short-form for P-256 signatures
    require(der[offset++] == 0x02.toByte()) { "invalid DER signature (r)" }
    val rLen = der[offset++].toInt() and 0xFF
    val r = der.copyOfRange(offset, offset + rLen)
    offset += rLen
    require(der[offset++] == 0x02.toByte()) { "invalid DER signature (s)" }
    val sLen = der[offset++].toInt() and 0xFF
    val s = der.copyOfRange(offset, offset + sLen)
    return leftPad32(r) + leftPad32(s)
}

private fun leftPad32(value: ByteArray): ByteArray {
    var start = 0
    while (start < value.size - 1 && value[start] == 0.toByte()) start++
    val trimmed = value.copyOfRange(start, value.size)
    val out = ByteArray(32)
    val copyLen = minOf(trimmed.size, 32)
    trimmed.copyInto(out, 32 - copyLen, trimmed.size - copyLen, trimmed.size)
    return out
}
