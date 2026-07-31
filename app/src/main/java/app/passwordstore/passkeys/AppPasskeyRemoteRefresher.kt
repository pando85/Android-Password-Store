/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.SharedPreferences
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.context.FilesDirPath
import app.passwordstore.injection.prefs.GitSecrets
import app.passwordstore.passkeys.storage.PasskeyRemoteRefresher
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.git.sshj.SshKey
import app.passwordstore.util.git.sshj.SshjConfig
import app.passwordstore.util.git.sshj.setUpBouncyCastleForSshj
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.asLog
import logcat.logcat
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.FingerprintVerifier
import net.schmizz.sshj.userauth.method.AuthPublickey
import net.schmizz.sshj.userauth.password.PasswordFinder
import net.schmizz.sshj.userauth.password.Resource
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.transport.CredentialItem
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.SshTransport
import org.eclipse.jgit.transport.Transport
import org.eclipse.jgit.transport.URIish
import org.eclipse.jgit.util.FS

@Singleton
class AppPasskeyRemoteRefresher
@Inject
constructor(
  private val gitSettings: GitSettings,
  @GitSecrets private val gitSecrets: SharedPreferences,
  @FilesDirPath private val filesDirPath: String,
  private val dispatcherProvider: DispatcherProvider,
) : PasskeyRemoteRefresher {

  override suspend fun refresh(): Result<Unit, Throwable> {
    if (gitSettings.url == null) return Err(IllegalStateException("Git URL is not set"))
    if (PasswordRepository.repository == null)
      return Err(IllegalStateException("Repository is not initialized"))
    return withContext(dispatcherProvider.io()) { executePull() }
  }

  private fun executePull(): Result<Unit, Throwable> {
    val repository =
      PasswordRepository.repository
        ?: return Err(IllegalStateException("Repository is not initialized"))
    val git = Git(repository)
    var sshSession: NonInteractiveSshSession? = null
    try {
      val pullCommand = git.pull().setRemote("origin").setRebase(gitSettings.rebaseOnPull)
      configureTransport(pullCommand) { session -> sshSession = session }
      val result = pullCommand.call()
      return if (result.mergeResult?.mergeStatus?.isSuccessful != false) {
        logcat { "Passkey remote refresh (pull) completed" }
        Ok(Unit)
      } else {
        Err(
          IllegalStateException(
            "Pull failed: ${result.mergeResult?.conflicts?.keys?.joinToString()}"
          )
        )
      }
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Passkey remote refresh failed: ${e.asLog()}" }
      return Err(e)
    } finally {
      sshSession?.close()
      git.close()
    }
  }

  private fun configureTransport(
    command: org.eclipse.jgit.api.TransportCommand<*, *>,
    onSessionCreated: (NonInteractiveSshSession) -> Unit = {},
  ) {
    command.setTransportConfigCallback { transport: Transport ->
      command.setTimeout(CONNECT_TIMEOUT)
      when (gitSettings.authMode) {
        AuthMode.SshKey -> configureSshTransport(transport, onSessionCreated)
        AuthMode.Password -> configureHttpsTransport(transport)
        AuthMode.None -> {}
      }
    }
  }

  private fun configureSshTransport(
    transport: Transport,
    onSessionCreated: (NonInteractiveSshSession) -> Unit,
  ) {
    if (transport !is SshTransport) return
    if (!SshKey.exists) throw IllegalStateException("SSH key not found")
    if (SshKey.mustAuthenticate)
      throw IllegalStateException("SSH key requires biometric authentication")
    val hostKeyFile = File(filesDirPath, ".host_key")
    if (!hostKeyFile.exists()) throw IllegalStateException("Host key not trusted yet")
    val hostKeyEntry = hostKeyFile.readText()
    val verifier = FingerprintVerifier.getInstance(hostKeyEntry)
    setUpBouncyCastleForSshj()
    val sshSessionFactory =
      object : org.eclipse.jgit.transport.SshSessionFactory() {
        override fun getSession(
          uri: URIish?,
          credentialsProvider: CredentialsProvider?,
          fs: FS?,
          tms: Int,
        ): org.eclipse.jgit.transport.RemoteSession {
          val ssh = SSHClient(SshjConfig())
          ssh.addHostKeyVerifier(verifier)
          val host = uri?.host ?: throw IllegalStateException("No host in URI")
          val port = uri.port.takeUnless { it == -1 } ?: 22
          val user = uri.user ?: "git"
          ssh.connect(host, port)
          val fixedUri =
            if (uri.host.contains('@')) {
              URIish()
                .setUser(uri.host.substringBeforeLast('@'))
                .setHost(uri.host.substringAfterLast('@'))
                .setPort(uri.port)
                .setPath(uri.path)
            } else uri
          val keyProvider =
            SshKey.provide(
              ssh,
              object : PasswordFinder {
                override fun reqPassword(resource: Resource<*>?): CharArray = charArrayOf()

                override fun shouldRetry(resource: Resource<*>?): Boolean = false
              },
            ) ?: throw IllegalStateException("Cannot load SSH key")
          ssh.auth(user, AuthPublickey(keyProvider))
          return NonInteractiveSshSession(ssh, fixedUri).also { onSessionCreated(it) }
        }

        override fun getType(): String = "NonInteractiveSshSessionFactory"
      }
    transport.sshSessionFactory = sshSessionFactory
  }

  private fun configureHttpsTransport(transport: Transport) {
    val password =
      AESEncryption.decrypt(
        gitSecrets.getString(PreferenceKeys.HTTPS_PASSWORD, null)?.toCharArray(),
        keyType = AESEncryption.KeyType.PERSISTENT,
      )
    if (password == null) throw IllegalStateException("HTTPS password not stored")
    transport.credentialsProvider =
      object : CredentialsProvider() {
        override fun isInteractive() = false

        override fun supports(vararg items: CredentialItem) = items.all {
          it is CredentialItem.Username || it is CredentialItem.Password
        }

        override fun get(uri: URIish?, vararg items: CredentialItem): Boolean {
          for (item in items) {
            when (item) {
              is CredentialItem.Username -> item.value = uri?.user
              is CredentialItem.Password -> item.value = password
              else -> return false
            }
          }
          return true
        }

        override fun reset(uri: URIish?) {}
      }
  }

  private companion object {
    const val CONNECT_TIMEOUT = 10
  }
}

private class NonInteractiveSshSession(
  private val ssh: SSHClient,
  @Suppress("unused") private val uri: URIish,
) : org.eclipse.jgit.transport.RemoteSession {

  private var currentSession: Session? = null

  override fun exec(commandName: String?, timeout: Int): Process {
    currentSession?.close()
    val session = ssh.startSession()
    currentSession = session
    return NonInteractiveSshProcess(session.exec(commandName), timeout.toLong())
  }

  override fun disconnect() {
    currentSession?.close()
    currentSession = null
  }

  fun close() {
    disconnect()
    ssh.close()
  }
}

private class NonInteractiveSshProcess(
  private val command: Session.Command,
  private val timeout: Long,
) : Process() {

  override fun waitFor(): Int {
    command.join(timeout, TimeUnit.SECONDS)
    command.close()
    return exitValue()
  }

  override fun destroy() = command.close()

  override fun getOutputStream(): OutputStream = command.outputStream

  override fun getErrorStream(): InputStream = command.errorStream

  override fun exitValue(): Int = command.exitStatus

  override fun getInputStream(): InputStream = command.inputStream
}
