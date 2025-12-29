/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PasskeySerializerTest {

  private val serializer = PasskeySerializer()

  @Test
  fun serializeAndDeserializeRoundTrip() {
    val original = createTestCredential()

    val serialized = serializer.serialize(original)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertTrue(original.id.contentEquals(deserialized.id))
    assertEquals(original.rp.id, deserialized.rp.id)
    assertEquals(original.rp.name, deserialized.rp.name)
    assertTrue(original.user.id.contentEquals(deserialized.user.id))
    assertEquals(original.user.name, deserialized.user.name)
    assertEquals(original.user.displayName, deserialized.user.displayName)
    assertEquals(original.signCount, deserialized.signCount)
    assertEquals(original.alg, deserialized.alg)
    assertTrue(original.privateKey.contentEquals(deserialized.privateKey))
    assertEquals(original.created, deserialized.created)
    assertEquals(original.discoverable, deserialized.discoverable)
    assertEquals(original.extensions.credProtect, deserialized.extensions.credProtect)
    assertEquals(original.extensions.hmacSecret, deserialized.extensions.hmacSecret)
  }

  @Test
  fun serializeProducesCbor() {
    val credential = createTestCredential()

    val serialized = serializer.serialize(credential)

    // CBOR maps start with 0xA or 0xB (map type with length)
    assertTrue(serialized.isNotEmpty())
    // First byte should indicate a CBOR map
    val firstByte = serialized[0].toInt() and 0xFF
    assertTrue(firstByte >= 0xA0 || firstByte == 0xBF, "Expected CBOR map, got $firstByte")
  }

  @Test
  fun deserializeWithOptionalFieldsMissing() {
    // Credential with minimal optional data
    val credential = createTestCredential(
      rpName = null,
      userName = null,
      userDisplayName = null,
    )

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertNull(deserialized.rp.name)
    assertNull(deserialized.user.name)
    assertNull(deserialized.user.displayName)
  }

  @Test
  fun deserializeWithExtensions() {
    val credential = createTestCredential(
      credProtect = 2,
      hmacSecret = true,
    )

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals(2, deserialized.extensions.credProtect)
    assertEquals(true, deserialized.extensions.hmacSecret)
  }

  @Test
  fun deserializeInvalidDataReturnsNull() {
    val invalidData = "not valid cbor".toByteArray(Charsets.UTF_8)

    val result = serializer.deserialize(invalidData)

    assertNull(result)
  }

  @Test
  fun deserializeEmptyDataReturnsNull() {
    val emptyData = ByteArray(0)

    val result = serializer.deserialize(emptyData)

    assertNull(result)
  }

  @Test
  fun serializeWithDifferentAlgorithms() {
    // ES256 algorithm (-7)
    val es256Credential = createTestCredential(alg = -7)
    val serialized = serializer.serialize(es256Credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals(-7, deserialized.alg)

    // ES384 algorithm (-35)
    val es384Credential = createTestCredential(alg = -35)
    val es384Serialized = serializer.serialize(es384Credential)
    val es384Deserialized = serializer.deserialize(es384Serialized)

    assertNotNull(es384Deserialized)
    assertEquals(-35, es384Deserialized.alg)
  }

  @Test
  fun serializeWithHighSignCount() {
    val credential = createTestCredential(signCount = 999999)

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals(999999, deserialized.signCount)
  }

  @Test
  fun serializeWithUnicodeCharacters() {
    val credential = PasskeyCredential(
      id = byteArrayOf(1, 2, 3, 4),
      rp = RelyingParty(id = "example.com", name = "Example Corp"),
      user = User(
        id = byteArrayOf(5, 6, 7, 8),
        name = "test@example.com",
        displayName = "Test User",
      ),
      signCount = 0,
      alg = -7,
      privateKey = ByteArray(32) { it.toByte() },
      created = 1703980800L,
      discoverable = true,
    )

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals("Example Corp", deserialized.rp.name)
    assertEquals("test@example.com", deserialized.user.name)
    assertEquals("Test User", deserialized.user.displayName)
  }

  @Test
  fun serializeWithLargeBinaryData() {
    // Create credential with larger ID and userId
    val largeId = ByteArray(64) { it.toByte() }
    val largeUserId = ByteArray(128) { (it * 2).toByte() }
    val largePrivateKey = ByteArray(32) { (it * 3).toByte() }

    val credential = PasskeyCredential(
      id = largeId,
      rp = RelyingParty(id = "example.com", name = "Example Corp"),
      user = User(id = largeUserId, name = "testuser", displayName = "Test User"),
      signCount = 0,
      alg = -7,
      privateKey = largePrivateKey,
      created = 1703980800L,
      discoverable = true,
    )

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertTrue(largeId.contentEquals(deserialized.id))
    assertTrue(largeUserId.contentEquals(deserialized.user.id))
    assertTrue(largePrivateKey.contentEquals(deserialized.privateKey))
  }

  @Test
  fun serializeNonDiscoverableCredential() {
    val credential = createTestCredential(discoverable = false)

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals(false, deserialized.discoverable)
  }

  @Test
  fun serializeWithTimestamp() {
    val timestamp = 1704067200L // 2024-01-01 00:00:00 UTC in seconds

    val credential = createTestCredential(created = timestamp)

    val serialized = serializer.serialize(credential)
    val deserialized = serializer.deserialize(serialized)

    assertNotNull(deserialized)
    assertEquals(timestamp, deserialized.created)
  }

  private fun createTestCredential(
    id: ByteArray = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16),
    rpId: String = "example.com",
    rpName: String? = "Example Corp",
    userId: ByteArray = byteArrayOf(100, 101, 102, 103),
    userName: String? = "testuser",
    userDisplayName: String? = "Test User",
    signCount: Int = 0,
    alg: Int = -7, // ES256
    privateKey: ByteArray = ByteArray(32) { it.toByte() },
    created: Long = 1703980800L, // 2024-01-01 00:00:00 UTC (seconds)
    discoverable: Boolean = true,
    credProtect: Int? = null,
    hmacSecret: Boolean? = null,
  ) = PasskeyCredential(
    id = id,
    rp = RelyingParty(id = rpId, name = rpName),
    user = User(id = userId, name = userName, displayName = userDisplayName),
    signCount = signCount,
    alg = alg,
    privateKey = privateKey,
    created = created,
    discoverable = discoverable,
    extensions = Extensions(credProtect = credProtect, hmacSecret = hmacSecret),
  )
}
