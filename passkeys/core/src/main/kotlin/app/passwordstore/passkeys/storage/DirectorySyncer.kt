/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import java.io.File
import java.io.FileDescriptor
import logcat.LogPriority
import logcat.logcat

public fun interface DirectorySyncer {

  public fun sync(dir: File)

  public companion object {
    public val PLATFORM: DirectorySyncer = PlatformDirectorySyncer()
  }
}

internal class PlatformDirectorySyncer : DirectorySyncer {

  override fun sync(dir: File) {
    val path = dir.absolutePath
    val androidOsSyncResult = tryAndroidOsSync(path)
    if (androidOsSyncResult) return
    syncViaUnixNativeDispatcher(path)
  }

  private fun tryAndroidOsSync(path: String): Boolean {
    return try {
      val osClass = Class.forName("android.system.Os")
      val structClass = Class.forName("android.system.OsConstants")
      val oRdonly = structClass.getField("O_RDONLY").getInt(null)
      val openMethod =
        osClass.getMethod("open", String::class.java, Int::class.java, Int::class.java)
      val fd = openMethod.invoke(null, path, oRdonly, 0) as FileDescriptor
      try {
        val fsyncMethod = osClass.getMethod("fsync", FileDescriptor::class.java)
        fsyncMethod.invoke(null, fd)
      } finally {
        try {
          val closeMethod = osClass.getMethod("close", FileDescriptor::class.java)
          closeMethod.invoke(null, fd)
        } catch (e: Exception) {
          logcat(LogPriority.WARN) { "Failed to close directory fd: ${e.message}" }
        }
      }
      true
    } catch (_: ClassNotFoundException) {
      false
    } catch (e: Exception) {
      val cause = e.cause ?: e
      throw DirectorySyncException(
        "Android Os directory fsync failed for $path: ${cause.message}",
        cause,
      )
    }
  }

  private fun syncViaUnixNativeDispatcher(path: String) {
    try {
      val nativeDispatcherClass = Class.forName("sun.nio.fs.UnixNativeDispatcher")
      val openMethod =
        nativeDispatcherClass.getDeclaredMethod(
          "open",
          ByteArray::class.java,
          Int::class.javaPrimitiveType,
          Int::class.javaPrimitiveType,
        )
      openMethod.isAccessible = true
      val pathBytes = path.toByteArray()
      val fd = openMethod.invoke(null, pathBytes, 0, 0) as Int
      if (fd < 0) {
        throw DirectorySyncException("Failed to open directory fd for $path: fd=$fd")
      }
      try {
        val fsyncMethod =
          nativeDispatcherClass.getDeclaredMethod("fsync", Int::class.javaPrimitiveType)
        fsyncMethod.isAccessible = true
        fsyncMethod.invoke(null, fd)
      } finally {
        try {
          val closeMethod =
            nativeDispatcherClass.getDeclaredMethod("close", Int::class.javaPrimitiveType)
          closeMethod.isAccessible = true
          closeMethod.invoke(null, fd)
        } catch (e: Exception) {
          logcat(LogPriority.WARN) { "Failed to close directory fd: ${e.message}" }
        }
      }
    } catch (e: DirectorySyncException) {
      throw e
    } catch (e: ClassNotFoundException) {
      throw DirectorySyncException(
        "Directory fsync not available on this platform: $path",
        e,
      )
    } catch (e: Exception) {
      val cause = e.cause ?: e
      throw DirectorySyncException(
        "Directory fsync failed for $path: ${cause.message}",
        cause,
      )
    }
  }
}

public class DirectorySyncException(
  message: String,
  cause: Throwable? = null,
) : RuntimeException(message, cause)
