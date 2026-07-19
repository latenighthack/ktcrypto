package com.latenighthack.ktcrypto

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/**
 * AES.generateKey was TODO() on iOS, crashing Sealing.seal (join-conversation flow) with
 * NotImplementedError, and InternalGCM required an externally-installed _aesGCMProvider that
 * nothing set. Regression guard for the native CryptoKit implementation. Wire format must match
 * JVM/JS: iv(12) ‖ ciphertext ‖ tag(16).
 */
class AESIosTest {

    @Test
    fun generateKeyProducesRandomKeyOfRequestedSize() = runBlocking {
        val key = AES.generateKey()
        assertEquals(32, key.encodePublic().size, "default key must be 256-bit")
        assertEquals(16, AES.generateKey(128).encodePublic().size)

        val other = AES.generateKey()
        assertTrue(!key.encodePublic().contentEquals(other.encodePublic()), "keys must not repeat")
    }

    @Test
    fun gcmRoundTripsAndMatchesWireFormat() = runBlocking {
        val key = AES.generateKey()
        val clearText = "attack at dawn".encodeToByteArray()

        val cipherText = AES.GCM.encrypt(key, clearText)
        assertEquals(12 + clearText.size + 16, cipherText.size, "must be iv(12) ‖ ciphertext ‖ tag(16)")

        val decrypted = AES.GCM.decrypt(key, cipherText)
        assertTrue(clearText.contentEquals(decrypted), "decrypt(encrypt()) must round-trip")
    }

    @Test
    fun gcmRejectsTamperedCipherText() = runBlocking {
        val key = AES.generateKey()
        val cipherText = AES.GCM.encrypt(key, "attack at dawn".encodeToByteArray())
        cipherText[cipherText.size - 1] = (cipherText[cipherText.size - 1] + 1).toByte()

        assertFails { AES.GCM.decrypt(key, cipherText) }
        Unit
    }
}
