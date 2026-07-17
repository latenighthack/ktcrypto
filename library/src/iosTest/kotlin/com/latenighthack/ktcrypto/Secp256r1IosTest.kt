package com.latenighthack.ktcrypto

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The iOS public-key encoding must match the JVM/Android SEC1 compressed form (33 bytes,
 * 0x02/0x03 ‖ X) — not CryptoKit's 32-byte compact representation. Regression guard for the
 * cross-platform room-id mismatch that crashed RoomKeying.publicKeyed with "got 32".
 */
class Secp256r1IosTest {

    @Test
    fun encodeProducesSec1CompressedAndRoundTrips() = runBlocking {
        val keyPair = Secp256r1KeyPair.generate()

        val encoded = keyPair.publicKey.encode()
        assertEquals(33, encoded.size, "iOS public key must encode to 33-byte SEC1 compressed")
        assertTrue(
            encoded[0] == 0x02.toByte() || encoded[0] == 0x03.toByte(),
            "SEC1 compressed prefix must be 0x02 or 0x03, was ${encoded[0]}",
        )

        val roundTripped = Secp256r1PublicKey.decode(encoded).encode()
        assertTrue(encoded.contentEquals(roundTripped), "decode(encode()) must round-trip to the same bytes")
    }
}
