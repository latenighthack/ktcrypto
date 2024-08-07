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

private val ecKeyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())

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
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA")
        ecdsaSign.initVerify(internalKey)
        ecdsaSign.update(message)

        val k = signature.size / 2
        val rBytes = BigInteger(1, signature.sliceArray(0 until k)).toByteArray()
        val sBytes = BigInteger(1, signature.sliceArray(k until k * 2)).toByteArray()

        // 2 byte header, 2 byes tag+len per field
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
        val ecdsaSign: Signature = Signature.getInstance("SHA256withECDSA")
        ecdsaSign.initSign(internalKey)
        ecdsaSign.update(message)

        // There doesn't seem to be a good way to specify what format we wish to export.
        //
        // We exploit the fact that the DER file structure will be identical for signature's, and so
        // we only need to parse what's relevant to us, and not impl a full Der decoder.
        //
        // Format: [SEQ|Constructed, RemainingLen][INTEGER_TAG,LEN]<r>[INTEGER_TAG,LEN]<s>
        //
        // We use this structure to identify where the R and S integers are stored in the signature.
        //
        // Both integers need to be the same length when exported into a raw key so readers can simply
        // divide the signature in half for the boundaries.
        //
        // Both integers are expected to be positive. More robust decoders will assert this when
        // reading out an EC signature (e.g. ECUtil.java).
        //
        // Further Reading:
        // https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question/57734#57734
        // https://stackoverflow.com/questions/48530316/what-is-the-output-format-of-the-sha256withecdsa-signature-algorithm
        // https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
        // sun.security.util.ECUtil.java (not avail on android)
        val derSig = ecdsaSign.sign()

        val r = BigInteger(1, derSig.sliceArray(4 until 4 + derSig[3]))
        val s = BigInteger(1, derSig.sliceArray(4 + derSig[3] + 2 until derSig.size))

        val rBytes = trimZeros(r.toByteArray())
        val sBytes = trimZeros(s.toByteArray())

        // r and s should occupy the same amount of space.
        //
        // note: BigInt encoding is big endian, so we calculate their dest position from the 'right'
        val k = rBytes.size.coerceAtLeast(sBytes.size)
        val result = ByteArray(k shl 1)
        rBytes.copyInto(result, k - rBytes.size)
        sBytes.copyInto(result, result.size - sBytes.size)

        return result
    }

    actual companion object {}
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

private fun trimZeros(b: ByteArray): ByteArray {
    var i = 0
    while ((i < b.size - 1) && b[i] == 0.toByte()) {
        i++
    }
    return b.sliceArray(i until b.size)
}
