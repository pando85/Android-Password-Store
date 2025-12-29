/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkey

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Serializer for passkey credentials using CBOR format.
 *
 * This format is compatible with Passless (https://github.com/pando85/passless)
 * to allow syncing passkeys between Android Password Store and Passless via git.
 *
 * CBOR structure matches Passless credential.rs:
 * {
 *   "id": <bytes>,
 *   "rp": { "id": <string>, "name": <string|null> },
 *   "user": { "id": <bytes>, "name": <string|null>, "display_name": <string|null> },
 *   "sign_count": <uint>,
 *   "alg": <int>,
 *   "private_key": <bytes>,
 *   "created": <int>,
 *   "discoverable": <bool>,
 *   "extensions": { "cred_protect": <uint|null>, "hmac_secret": <bool|null> }
 * }
 */
@Singleton
public class PasskeySerializer @Inject constructor() {

  /**
   * Serialize a PasskeyCredential to CBOR bytes.
   *
   * @param credential The credential to serialize
   * @return CBOR-encoded bytes (NOT encrypted - caller must encrypt with PGP)
   */
  public fun serialize(credential: PasskeyCredential): ByteArray {
    val outputStream = ByteArrayOutputStream()

    // Build the root map manually to handle negative integers properly
    val rootMap = Map()

    // id: bytes
    rootMap.put(UnicodeString("id"), ByteString(credential.id))

    // rp: map
    val rpMap = Map()
    rpMap.put(UnicodeString("id"), UnicodeString(credential.rp.id))
    credential.rp.name?.let { rpMap.put(UnicodeString("name"), UnicodeString(it)) }
    rootMap.put(UnicodeString("rp"), rpMap)

    // user: map
    val userMap = Map()
    userMap.put(UnicodeString("id"), ByteString(credential.user.id))
    credential.user.name?.let { userMap.put(UnicodeString("name"), UnicodeString(it)) }
    credential.user.displayName?.let { userMap.put(UnicodeString("display_name"), UnicodeString(it)) }
    rootMap.put(UnicodeString("user"), userMap)

    // sign_count: uint
    rootMap.put(UnicodeString("sign_count"), UnsignedInteger(credential.signCount.toLong()))

    // alg: int (can be negative, e.g., -7 for ES256)
    // NegativeInteger expects the actual negative value
    val algValue: DataItem = if (credential.alg >= 0) {
      UnsignedInteger(credential.alg.toLong())
    } else {
      NegativeInteger(credential.alg.toLong())
    }
    rootMap.put(UnicodeString("alg"), algValue)

    // private_key: bytes
    rootMap.put(UnicodeString("private_key"), ByteString(credential.privateKey))

    // created: int (Unix timestamp seconds)
    rootMap.put(UnicodeString("created"), UnsignedInteger(credential.created))

    // discoverable: bool
    rootMap.put(UnicodeString("discoverable"), if (credential.discoverable) SimpleValue.TRUE else SimpleValue.FALSE)

    // extensions: map
    val extensionsMap = Map()
    credential.extensions.credProtect?.let {
      extensionsMap.put(UnicodeString("cred_protect"), UnsignedInteger(it.toLong()))
    }
    credential.extensions.hmacSecret?.let {
      extensionsMap.put(UnicodeString("hmac_secret"), if (it) SimpleValue.TRUE else SimpleValue.FALSE)
    }
    rootMap.put(UnicodeString("extensions"), extensionsMap)

    CborEncoder(outputStream).encode(rootMap)

    return outputStream.toByteArray()
  }

  /**
   * Deserialize CBOR bytes to a PasskeyCredential.
   *
   * @param data CBOR-encoded bytes (NOT encrypted - caller must decrypt with PGP first)
   * @return The deserialized credential, or null if parsing fails
   */
  public fun deserialize(data: ByteArray): PasskeyCredential? {
    return try {
      val inputStream = ByteArrayInputStream(data)
      val dataItems = CborDecoder(inputStream).decode()

      if (dataItems.isEmpty()) return null

      val root = dataItems[0]
      if (root.majorType != MajorType.MAP) return null

      val map = root as Map

      // Extract required fields
      val id = map.getBytes("id") ?: return null
      val rpMap = map.getMap("rp") ?: return null
      val userMap = map.getMap("user") ?: return null
      val signCount = map.getUnsignedInt("sign_count")?.toInt() ?: 0
      val alg = map.getInt("alg")?.toInt() ?: -7
      val privateKey = map.getBytes("private_key") ?: return null
      val created = map.getInt("created") ?: System.currentTimeMillis() / 1000
      val discoverable = map.getBoolean("discoverable") ?: true

      // Parse rp
      val rpId = rpMap.getString("id") ?: return null
      val rpName = rpMap.getString("name")

      // Parse user
      val userId = userMap.getBytes("id") ?: return null
      val userName = userMap.getString("name")
      val userDisplayName = userMap.getString("display_name")

      // Parse extensions (optional)
      val extensionsMap = map.getMap("extensions")
      val credProtect = extensionsMap?.getUnsignedInt("cred_protect")?.toInt()
      val hmacSecret = extensionsMap?.getBoolean("hmac_secret")

      PasskeyCredential(
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
    } catch (e: Exception) {
      null
    }
  }

  // === CBOR Map Extension Functions ===

  private fun Map.getBytes(key: String): ByteArray? {
    val item = get(UnicodeString(key)) ?: return null
    return if (item is ByteString) item.bytes else null
  }

  private fun Map.getString(key: String): String? {
    val item = get(UnicodeString(key)) ?: return null
    return if (item is UnicodeString) item.string else null
  }

  private fun Map.getUnsignedInt(key: String): Long? {
    val item = get(UnicodeString(key)) ?: return null
    return when (item) {
      is UnsignedInteger -> item.value.toLong()
      is NegativeInteger -> item.value.toLong()
      else -> null
    }
  }

  private fun Map.getInt(key: String): Long? {
    val item = get(UnicodeString(key)) ?: return null
    return when (item) {
      is UnsignedInteger -> item.value.toLong()
      // NegativeInteger.value returns the actual negative value directly
      is NegativeInteger -> item.value.toLong()
      else -> null
    }
  }

  private fun Map.getBoolean(key: String): Boolean? {
    val item = get(UnicodeString(key)) ?: return null
    return when (item) {
      SimpleValue.TRUE -> true
      SimpleValue.FALSE -> false
      else -> null
    }
  }

  private fun Map.getMap(key: String): Map? {
    val item = get(UnicodeString(key)) ?: return null
    return if (item is Map) item else null
  }
}
