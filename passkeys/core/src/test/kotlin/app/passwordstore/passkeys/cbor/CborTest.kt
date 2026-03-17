/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.cbor

import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CborTest {

  @Test
  fun `parse fixture credential 1`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/07b36924d8924098bb427039d7d0f43b86b4cb52a9dec9aab04bf47472e02d7b.bin"
        )!!
        .readBytes()
    val cbor = Cbor.parse(bytes)
    val map = cbor.asMap()

    assertEquals(
      setOf(
        "id",
        "rp",
        "user",
        "sign_count",
        "alg",
        "private_key",
        "created",
        "discoverable",
        "extensions",
      ),
      map.keys,
    )

    val id = map.getBytes("id")
    assertNotNull(id)
    assertEquals(32, id!!.size)
    assertEquals(0x07, id[0].toInt() and 0xFF)
    assertEquals(0xb3, id[1].toInt() and 0xFF)

    val rp = map.getMap("rp")
    assertNotNull(rp)
    assertEquals("webauthn.io", rp!!.getString("id"))
    assertTrue(rp.isNull("name"))

    val user = map.getMap("user")
    assertNotNull(user)
    val userId = user!!.getBytes("id")
    assertNotNull(userId)
    assertEquals("webauthnio-soft-fido2", String(userId!!, Charsets.UTF_8))
    assertEquals("soft-fido2", user.getString("name"))
    assertTrue(user.isNull("display_name"))

    assertEquals(0, map.getInt("sign_count"))
    assertEquals(-8, map.getInt("alg"))

    val privateKey = map.getBytes("private_key")
    assertNotNull(privateKey)
    assertEquals(32, privateKey!!.size)

    assertNotNull(map.getLong("created"))
    assertTrue(map.getBoolean("discoverable") ?: false)

    val extensions = map.getMap("extensions")
    assertNotNull(extensions)
    assertEquals(3, extensions!!.getInt("cred_protect"))
    assertTrue(extensions.isNull("hmac_secret"))
  }

  @Test
  fun `parse fixture credential 2`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/1381816530c267f00fb7d8a844b65f765cbbc059d8d7c695a40b7a1dea48f139.bin"
        )!!
        .readBytes()
    val cbor = Cbor.parse(bytes)
    val map = cbor.asMap()

    assertEquals("webauthn.io", map.getMap("rp")?.getString("id"))
    assertEquals("passless", map.getMap("user")?.getString("name"))
    assertEquals(-8, map.getInt("alg"))
    assertEquals(3, map.getMap("extensions")?.getInt("cred_protect"))
  }

  @Test
  fun `roundtrip credential`() {
    val originalBytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/07b36924d8924098bb427039d7d0f43b86b4cb52a9dec9aab04bf47472e02d7b.bin"
        )!!
        .readBytes()
    val parsed = Cbor.parse(originalBytes)
    val reencoded = parsed.toBytes()

    val reparsed = Cbor.parse(reencoded)
    val originalMap = parsed.asMap()
    val reparsedMap = reparsed.asMap()

    assertArrayEquals(originalMap.getBytes("id"), reparsedMap.getBytes("id"))
    assertArrayEquals(originalMap.getBytes("private_key"), reparsedMap.getBytes("private_key"))
    assertEquals(originalMap.getString("rp"), reparsedMap.getString("rp"))
    assertEquals(originalMap.getInt("alg"), reparsedMap.getInt("alg"))
  }

  @Test
  fun `byte array as integer array`() {
    val bytes = byteArrayOf(0x01, 0x02, 0x03, 0xFF.toByte())
    val cborArray = bytes.toCborIntegerArray()

    val elements = cborArray.value.toList()
    assertEquals(4, elements.size)
    assertEquals(BigInteger.valueOf(1), (elements[0] as CborValue.UnsignedInteger).value)
    assertEquals(BigInteger.valueOf(2), (elements[1] as CborValue.UnsignedInteger).value)
    assertEquals(BigInteger.valueOf(3), (elements[2] as CborValue.UnsignedInteger).value)
    assertEquals(BigInteger.valueOf(255), (elements[3] as CborValue.UnsignedInteger).value)

    val recovered = cborArray.value.toByteArray()
    assertArrayEquals(bytes, recovered)
  }

  @Test
  fun `write and parse simple map`() {
    val map =
      CborMap.create().apply {
        toMutableMap()["hello"] = CborValue.TextString("world")
        toMutableMap()["count"] = CborValue.UnsignedInteger(BigInteger.valueOf(42))
        toMutableMap()["negative"] = CborValue.NegativeInteger(BigInteger.valueOf(-7))
        toMutableMap()["flag"] = CborValue.True
        toMutableMap()["bytes"] = byteArrayOf(0x01, 0x02, 0x03).toCborIntegerArray()
      }

    val cbor = Cbor.fromMap(map)
    val bytes = cbor.toBytes()

    val parsed = Cbor.parse(bytes).asMap()
    assertEquals("world", parsed.getString("hello"))
    assertEquals(42, parsed.getInt("count"))
    assertEquals(-7, parsed.getInt("negative"))
    assertTrue(parsed.getBoolean("flag") ?: false)
    assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03), parsed.getBytes("bytes"))
  }
}
