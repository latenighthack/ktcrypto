package com.latenighthack.ktcrypto

import com.latenighthack.ktcrypto.tools.fromBase64String
import kotlinx.coroutines.await
import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Int8Array
import kotlin.js.Promise

private val ecdhImplementation = object : KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> {
    override suspend fun sharedSecret(privateKey: Secp256r1PrivateKey, publicKey: Secp256r1PublicKey): ByteArray {
        var result: ByteArray? = null
        val publicKey = publicKey
        val privateKey = privateKey
        val arrayBufferData = (js(
            """
            crypto.subtle.deriveBits({ "name": "ECDH", "public": publicKey.internalKey}, privateKey.internalKey, 256);
            """
        ) as Promise<*>).await() as ArrayBuffer

        return Int8Array(arrayBufferData).unsafeCast<ByteArray>()
    }
}

actual val Secp256r1.Companion.ECDH: KeyAgreement<Secp256r1PublicKey, Secp256r1PrivateKey> get() = ecdhImplementation

actual class Secp256r1KeyPair(
    actual override val publicKey: Secp256r1PublicKey,
    actual override val privateKey: Secp256r1PrivateKey
) : KeyPair<Secp256r1PublicKey, Secp256r1PrivateKey> {
    actual companion object
}

actual suspend fun Secp256r1KeyPair.Companion.generate(): Secp256r1KeyPair {
    val cryptoKeyPair = (js(
        """
        crypto.subtle.generateKey({ "name": "ECDH", "namedCurve": "P-256"}, true, ["deriveKey", "deriveBits"]);
        """
    ) as Promise<*>).await().asDynamic()

    return Secp256r1KeyPair(
        Secp256r1PublicKey(cryptoKeyPair.publicKey),
        Secp256r1PrivateKey(cryptoKeyPair.privateKey),
    )
}

actual suspend fun Secp256r1KeyPair.Companion.fromPrivateKey(raw: ByteArray): Secp256r1KeyPair? {
    val pkcs8 = encodePKCS8Private(raw)
    val cryptoKeyPair = (js(
        """
        crypto.subtle.importKey("pkcs8", pkcs8, { "name": "ECDH", "namedCurve": "P-256" }, true, ["deriveKey", "deriveBits"]).then(function(priv) {
            return crypto.subtle.exportKey("jwk", priv, { "name": "ECDH", "namedCurve": "P-256" }, true, ["deriveKey", "deriveBits"]).then(function(exported) {
                delete exported.d;

                return crypto.subtle.importKey("jwk", exported, { "name": "ECDH", "namedCurve": "P-256" }, true, []).then(function(pub) {
                    return {private: priv, public: pub}
                });
            })
        });
        """
    ) as Promise<*>).await().asDynamic()

    return Secp256r1KeyPair(
        Secp256r1PublicKey(cryptoKeyPair.public),
        Secp256r1PrivateKey(cryptoKeyPair.private),
    )
}

actual class Secp256r1PublicKey(val internalKey: dynamic) : PublicKey {
    actual override suspend fun verify(message: ByteArray, signature: ByteArray): Boolean {
        val internalKey = this.internalKey
        val signature = signature
        val message = message

        return (js(
            """
            crypto.subtle.exportKey('raw', internalKey)
                .then(function(pubKey) {
                    return crypto.subtle.importKey('raw', pubKey, { name: 'ECDSA', namedCurve: 'P-256'}, true, ["verify"])
                })
                .then(function(signKey) {
                    return crypto.subtle.verify({name: "ECDSA", hash: {name: "SHA-256"}}, signKey, signature, message);
                })
            """
        ) as Promise<*>).await() as Boolean
    }

    actual companion object {}
}

actual suspend fun Secp256r1PublicKey.Companion.decode(encodedKey: ByteArray): Secp256r1PublicKey {
    val decodedKey = (js(
        """
        crypto.subtle.importKey("raw", encodedKey, { "name": "ECDH", "namedCurve": "P-256" }, true, [])
        """
    ) as Promise<*>).await().asDynamic()

    return Secp256r1PublicKey(decodedKey)
}

actual suspend fun Secp256r1PublicKey.encode(): ByteArray {
    val internalKey = this.internalKey
    val arrayBufferData = (js(
        """
        crypto.subtle.exportKey('raw', internalKey).then(function(exportedkey) {
            var u8full = new Uint8Array(exportedkey);
            var len = u8full.byteLength;
            var u8 = u8full.slice(0, 1 + len >>> 1); // drop `y`
            u8[0] = 0x2 | (u8full[len-1] & 0x01); // encode sign of `y` in first bit
            
            return u8.buffer;
        });
        """
    ) as Promise<*>).await() as ArrayBuffer

    return Int8Array(arrayBufferData).unsafeCast<ByteArray>()
}

actual class Secp256r1PrivateKey(val internalKey: dynamic) : PrivateKey {
    actual override suspend fun sign(message: ByteArray): ByteArray {
        val arrayByfferData = (js(
            """
            crypto.subtle.exportKey('pkcs8', internalKey.privateKey)
                .then(function(privKey) {
                    crypto.subtle.importKey('pkcs8', privKey, { name: 'ECDSA', namedCurve: 'P-256'}, true, ["sign"])
                })
                .then(function(signKey) {
                    crypto.subtle.sign({name: "ECDSA", hash: {name: "SHA-256"}}, signKey, message);
                })
            """
        ) as Promise<*>).await() as ArrayBuffer

        return Int8Array(arrayByfferData).unsafeCast<ByteArray>()
    }

    actual companion object {}
}

actual suspend fun Secp256r1PrivateKey.Companion.fromRaw(raw: ByteArray): Secp256r1PrivateKey {
    val pkcs8 = encodePKCS8Private(raw)
    val decoded = (js(
        """
        crypto.subtle.importKey("pkcs8", pkcs8, { "name": "ECDH", "namedCurve": "P-256" }, true, ["deriveKey", "deriveBits"])
        """
    ) as Promise<*>).await().asDynamic()

    return Secp256r1PrivateKey(decoded)
}

actual suspend fun Secp256r1PrivateKey.encode(): ByteArray {
    val internalKey = this.internalKey
    val dB64Url = (js(
        """
        crypto.subtle.exportKey("jwk", internalKey, { "name": "ECDH", "namedCurve": "P-256" }, true, ["deriveKey", "deriveBits"]).then(function(exported) {
            return exported.d; // base64url
        });
    """
    ) as Promise<*>).await() as String

    return dB64Url.fromBase64String()
}
