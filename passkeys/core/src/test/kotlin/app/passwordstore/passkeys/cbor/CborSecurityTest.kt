/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.cbor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class CborSecurityTest {

  @Test
  fun `duplicate map key is rejected`() {
    val map = CborMap.from(
      mapOf(
        "a" to CborValue.UnsignedInteger(java.math.BigInteger.ONE),
        "b" to CborValue.UnsignedInteger(java.math.BigInteger.TWO),
      )
    )
    val bytes = Cbor.fromMap(map).toBytes()
    val duplicateMapBytes = injectDuplicateKey(bytes, "a", "b")
    try {
      Cbor.parse(duplicateMapBytes)
      fail("Expected CborException for duplicate key")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Duplicate key"))
    }
  }

  @Test
  fun `trailing data after root object is rejected`() {
    val map = CborMap.from(
      mapOf("key" to CborValue.TextString("value"))
    )
    val bytes = Cbor.fromMap(map).toBytes()
    val withTrailing = bytes + byteArrayOf(0x00, 0x01, 0x02)
    try {
      Cbor.parse(withTrailing)
      fail("Expected CborException for trailing data")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Trailing data"))
    }
  }

  @Test
  fun `trailing data allowed when option disabled`() {
    val map = CborMap.from(
      mapOf("key" to CborValue.TextString("value"))
    )
    val bytes = Cbor.fromMap(map).toBytes()
    val withTrailing = bytes + byteArrayOf(0x00, 0x01, 0x02)
    val options = CborParseOptions(rejectTrailingData = false)
    val result = Cbor.parse(withTrailing, options)
    assertEquals("value", result.asMap().getString("key"))
  }

  @Test
  fun `depth at limit is accepted`() {
    val options = CborParseOptions(maxDepth = 3)
    val deeplyNested = buildNestedArray(depth = 3)
    Cbor.parse(deeplyNested, options)
  }

  @Test
  fun `depth exceeding limit is rejected`() {
    val options = CborParseOptions(maxDepth = 2)
    val deeplyNested = buildNestedArray(depth = 3)
    try {
      Cbor.parse(deeplyNested, options)
      fail("Expected CborException for depth exceeded")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("depth"))
    }
  }

  @Test
  fun `collection at limit is accepted`() {
    val options = CborParseOptions(maxCollectionItems = 5)
    val array = buildArray(items = 5)
    Cbor.parse(array, options)
  }

  @Test
  fun `collection exceeding limit is rejected`() {
    val options = CborParseOptions(maxCollectionItems = 5)
    val array = buildArray(items = 6)
    try {
      Cbor.parse(array, options)
      fail("Expected CborException for collection size exceeded")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Array size"))
    }
  }

  @Test
  fun `oversized byte string is rejected`() {
    val options = CborParseOptions(maxStringBytes = 10)
    val largeBytes = buildByteString(size = 11)
    try {
      Cbor.parse(largeBytes, options)
      fail("Expected CborException for oversized byte string")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Byte string"))
    }
  }

  @Test
  fun `oversized text string is rejected`() {
    val options = CborParseOptions(maxStringBytes = 10)
    val largeText = buildTextString("hello world!!")
    try {
      Cbor.parse(largeText, options)
      fail("Expected CborException for oversized text string")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Text string"))
    }
  }

  @Test
  fun `indefinite length array is rejected`() {
    val indefiniteArray = byteArrayOf(
      0x9f.toByte(),
      0x01,
      0x02,
      0xff.toByte(),
    )
    try {
      Cbor.parse(indefiniteArray)
      fail("Expected CborException for indefinite length")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Indefinite"))
    }
  }

  private fun injectDuplicateKey(originalBytes: ByteArray, existingKey: String, newKey: String): ByteArray {
    val extraEntry = CborMap.from(
      mapOf(newKey to CborValue.UnsignedInteger(java.math.BigInteger.valueOf(99)))
    )
    val extraBytes = Cbor.fromMap(extraEntry).toBytes()
    val extraMapContent = extraBytes.copyOfRange(2, extraBytes.size)
    val mapHeader = originalBytes[0].toInt() and 0xFF
    val currentCount = mapHeader and 0x1F
    val newHeader = (mapHeader and 0xE0) or (currentCount + 1)
    return byteArrayOf(newHeader.toByte()) + originalBytes.copyOfRange(1, originalBytes.size) + extraMapContent
  }

  private fun buildNestedArray(depth: Int): ByteArray {
    if (depth == 0) {
      return Cbor.fromArray(CborArray.from(listOf())).toBytes()
    }
    val inner = buildNestedArray(depth - 1)
    val array = CborValue.Array(CborArray.from(listOf(Cbor.parse(inner, CborParseOptions(rejectTrailingData = false)).asArray().toList().let { CborValue.Array(CborArray.from(it)) })))
    return Cbor.fromValue(array).toBytes()
  }

  private fun buildArray(items: Int): ByteArray {
    val elements = (0 until items).map {
      CborValue.UnsignedInteger(java.math.BigInteger.valueOf(it.toLong()))
    }
    return Cbor.fromArray(CborArray.from(elements)).toBytes()
  }

  private fun buildByteString(size: Int): ByteArray {
    val data = ByteArray(size) { it.toByte() }
    val value = CborValue.ByteString(data)
    return Cbor.fromValue(value).toBytes()
  }

  private fun buildTextString(text: String): ByteArray {
    val value = CborValue.TextString(text)
    return Cbor.fromValue(value).toBytes()
  }
}
