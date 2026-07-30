/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.Context
import android.content.SharedPreferences
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.prefs.GitSecrets
import app.passwordstore.passkeys.storage.GitSyncResult
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.RepositoryGenerationProvider
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.git.sshj.SshKey
import app.passwordstore.util.git.sshj.SshjConfig
import app.passwordstore.util.git.sshj.normalizeForSshj
import app.passwordstore.util.git.sshj.parseSshPublicKey
import app.passwordstore.util.git.sshj.setUpBouncyCastleForSshj
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.runCatching
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.FingerprintVerifier
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.method.AuthPassword
import net.schmizz.sshj.userauth.method.AuthPublickey
import net.schmizz.sshj.userauth.password.PasswordFinder
import net.schmizz.sshj.userauth.password.Resource
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.transport.CredentialItem
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.SshTransport
import org.eclipse.jgit.transport.Transport
import org.eclipse.jgit.transport.TransportHttp
import org.eclipse.jgit.transport.URIish
import org.eclipse.jgit.util.FS

class PasskeySyncWorker(
  private val appContext: Context,
  params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

  private val hiltEntryPoint by unsafeLazy {
    EntryPointAccessors.fromApplication(appContext, PasskeySyncWorkerEntryPoint::class.java)
  }

  override suspend fun doWork(): androidx.work.ListenableWorker.Result {
    return runCatching {
        val repository =
          PasswordRepository.repository
            ?: throw IllegalStateException("Password repository is not initialized")
        val git = Git(repository)
        val gitSettings = hiltEntryPoint.gitSettings()
        val dispatcherProvider = hiltEntryPoint.dispatcherProvider()
        val passkeyRepositoryState = hiltEntryPoint.passkeyRepositoryState()
        val generationProvider = hiltEntryPoint.generationProvider()
        val gitSecrets = hiltEntryPoint.gitSecrets()
        val hostKeyFile = File(appContext.filesDir, ".host_key")
        val authMode = gitSettings.authMode
        val rebase = gitSettings.rebaseOnPull
        val useMultiplexing = gitSettings.useMultiplexing

        withContext(dispatcherProvider.io()) {
          val oldHead = generationProvider.currentGitHead()

          if (useMultiplexing) {
            executeSync(git, gitSettings, hostKeyFile, authMode, rebase, gitSecrets)
          } else {
            executePull(git, gitSettings, hostKeyFile, authMode, rebase, gitSecrets)
            executePush(git, hostKeyFile, authMode, gitSecrets)
          }

          val newHead = generationProvider.currentGitHead()
          val syncResult =
            GitSyncResult(
              oldHead = oldHead,
              newHead = newHead,
              worktreeChanged = oldHead != newHead,
              conflicts = emptyList(),
            )
          passkeyRepositoryState.onGitSyncCompleted(syncResult)
          generationProvider.bumpWorktreeGeneration()
          logcat { "Passkey auto-sync completed" }
        }
      }
      .fold(
        success = { androidx.work.ListenableWorker.Result.success() },
        failure = {
          logcat(LogPriority.WARN) { "Passkey auto-sync failed: ${it.message}" }
          androidx.work.ListenableWorker.Result.failure()
        },
      )
  }

  private fun stageAndCommit(git: Git, gitSettings: GitSettings) {
    git.add().addFilepattern(".").call()
    val status = git.status().call()
    if (status.uncommittedChanges.isNotEmpty()) {
      val name = gitSettings.authorName.ifEmpty { "root" }
      val email = gitSettings.authorEmail.ifEmpty { "localhost" }
      val identity = PersonIdent(name, email)
      git
        .commit()
        .setAll(true)
        .setMessage("[Android Password Store] Sync")
        .setAuthor(identity)
        .setCommitter(identity)
        .call()
    }
  }

  private fun executeSync(
    git: Git,
    gitSettings: GitSettings,
    hostKeyFile: File,
    authMode: AuthMode,
    rebase: Boolean,
    gitSecrets: SharedPreferences,
  ) {
    stageAndCommit(git, gitSettings)
    configureTransport(git.pull(), hostKeyFile, authMode, gitSecrets)
      .setRebase(rebase)
      .setRemote("origin")
      .call()
    configureTransport(git.push().setPushAll(), hostKeyFile, authMode, gitSecrets)
      .setRemote("origin")
      .call()
  }

  private fun executePull(
    git: Git,
    gitSettings: GitSettings,
    hostKeyFile: File,
    authMode: AuthMode,
    rebase: Boolean,
    gitSecrets: SharedPreferences,
  ) {
    stageAndCommit(git, gitSettings)
    configureTransport(git.pull(), hostKeyFile, authMode, gitSecrets)
      .setRebase(rebase)
      .setRemote("origin")
      .call()
  }

  private fun executePush(
    git: Git,
    hostKeyFile: File,
    authMode: AuthMode,
    gitSecrets: SharedPreferences,
  ) {
    configureTransport(git.push().setPushAll(), hostKeyFile, authMode, gitSecrets)
      .setRemote("origin")
      .call()
  }

  private fun <T : org.eclipse.jgit.api.TransportCommand<*, *>> configureTransport(
    command: T,
    hostKeyFile: File,
    authMode: AuthMode,
    gitSecrets: SharedPreferences,
  ): T {
    command.setTransportConfigCallback { transport: Transport ->
      when (transport) {
        is SshTransport -> {
          transport.sshSessionFactory =
            createHeadlessSshSessionFactory(hostKeyFile, authMode, gitSecrets)
        }
        is TransportHttp -> {
          if (authMode == AuthMode.Password) {
            val storedPassword = getStoredHttpsPassword(gitSecrets)
            if (storedPassword != null) {
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
                        is CredentialItem.Password -> item.value = storedPassword.toCharArray()
                        else -> return false
                      }
                    }
                    return true
                  }

                  override fun reset(uri: URIish?) {}
                }
            }
          }
        }
      }
      command.setTimeout(CONNECT_TIMEOUT)
    }
    return command
  }

  private fun createHeadlessSshSessionFactory(
    hostKeyFile: File,
    authMode: AuthMode,
    gitSecrets: SharedPreferences,
  ): org.eclipse.jgit.transport.SshSessionFactory {
    return object : org.eclipse.jgit.transport.SshSessionFactory() {
      override fun getSession(
        uri: URIish?,
        credentialsProvider: CredentialsProvider?,
        fs: FS?,
        tms: Int,
      ): org.eclipse.jgit.transport.RemoteSession {
        setUpBouncyCastleForSshj()
        val ssh = SSHClient(SshjConfig())
        if (hostKeyFile.exists()) {
          val hostKeyEntry = hostKeyFile.readText()
          ssh.addHostKeyVerifier(FingerprintVerifier.getInstance(hostKeyEntry))
        } else {
          throw IOException(
            "Host key not verified; cannot perform background sync without prior host key trust"
          )
        }
        val host = uri?.host ?: throw IOException("No host in URI")
        val port = uri.port.takeUnless { it == -1 } ?: 22
        ssh.connect(host, port)
        if (!ssh.isConnected) throw IOException("SSH connection failed")

        when (authMode) {
          AuthMode.SshKey -> {
            if (SshKey.mustAuthenticate) {
              throw IOException(
                "SSH key requires biometric authentication; cannot perform background sync"
              )
            }
            val keyProvider =
              loadSshKeyNonInteractive(ssh, gitSecrets)
                ?: throw IOException("Cannot load SSH key non-interactively")
            ssh.auth(uri.user ?: "git", AuthPublickey(keyProvider))
          }
          AuthMode.Password -> {
            val password =
              getStoredHttpsPassword(gitSecrets)
                ?: throw IOException("No stored password for SSH password authentication")
            ssh.auth(
              uri.user ?: "git",
              AuthPassword(
                object : PasswordFinder {
                  override fun reqPassword(resource: Resource<*>?) = password.toCharArray()

                  override fun shouldRetry(resource: Resource<*>?) = false
                }
              ),
            )
          }
          AuthMode.None -> {}
        }

        return HeadlessRemoteSession(ssh)
      }

      override fun getType(): String = "HeadlessSshSessionFactory"
    }
  }

  private fun loadSshKeyNonInteractive(
    ssh: SSHClient,
    gitSecrets: SharedPreferences,
  ): KeyProvider? {
    return runCatching {
        when (SshKey.type) {
          SshKey.Type.KeystoreNative -> {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val publicKey =
              keyStore.getCertificate("sshkey")?.publicKey
                ?: throw NullPointerException("No public key in keystore")
            val privateKey =
              keyStore.getKey("sshkey", null) as? PrivateKey
                ?: throw NullPointerException("No private key in keystore")
            SecurityUtils.setRegisterBouncyCastle(false)
            SecurityUtils.setSecurityProvider(null)
            ssh.loadKeys(KeyPair(normalizeForSshj(publicKey), privateKey))
          }
          SshKey.Type.KeystoreWrappedEd25519 -> {
            val publicKeyText =
              SshKey.sshPublicKey ?: throw NullPointerException("No public key file")
            val publicKey =
              parseSshPublicKey(publicKeyText)
                ?: throw NullPointerException("Cannot parse public key")
            val encrypted = gitSecrets.getString("sshkey", "false:")?.split(":", limit = 2)
            val mustAuth = encrypted?.getOrNull(0) == "true"
            if (mustAuth) {
              throw IOException("SSH key requires authentication; cannot load non-interactively")
            }
            val privateKeyEncoded =
              AESEncryption.decryptToByteArray(
                encrypted?.getOrNull(1)?.toCharArray(),
                KeyType.PERSISTENT,
              )
            val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyEncoded))
            SecurityUtils.setRegisterBouncyCastle(true)
            SecurityUtils.setSecurityProvider(BouncyCastleProvider.PROVIDER_NAME)
            ssh.loadKeys(KeyPair(publicKey, privateKey))
          }
          SshKey.Type.Imported -> {
            val privateKeyFile = File(appContext.filesDir, ".ssh_key")
            if (!privateKeyFile.exists()) throw IOException("Imported SSH key file not found")
            val passphrase =
              gitSecrets
                .getString(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE, null)
                ?.takeIf { AESEncryption.isHardwareBacked(KeyType.PERSISTENT) }
                ?.let {
                  AESEncryption.decrypt(it.toCharArray(), keyType = KeyType.PERSISTENT)
                    ?.concatToString()
                }
            val passwordFinder =
              object : PasswordFinder {
                override fun reqPassword(resource: Resource<*>?) =
                  passphrase?.toCharArray() ?: charArrayOf()

                override fun shouldRetry(resource: Resource<*>?) = false
              }
            ssh.loadKeys(privateKeyFile.absolutePath, passwordFinder)
          }
          SshKey.Type.ImportedPGP -> {
            throw IOException("PGP-backed SSH key requires interactive authentication")
          }
          null -> throw IOException("No SSH key configured")
        }
      }
      .fold(
        success = { it },
        failure = {
          logcat(LogPriority.WARN) { "Failed to load SSH key non-interactively: ${it.message}" }
          null
        },
      )
  }

  private fun getStoredHttpsPassword(gitSecrets: SharedPreferences): String? {
    val encrypted = gitSecrets.getString(PreferenceKeys.HTTPS_PASSWORD, null) ?: return null
    return if (AESEncryption.isHardwareBacked(KeyType.PERSISTENT)) {
      AESEncryption.decrypt(encrypted.toCharArray(), keyType = KeyType.PERSISTENT)?.concatToString()
    } else null
  }

  private class HeadlessRemoteSession(private val ssh: SSHClient) :
    org.eclipse.jgit.transport.RemoteSession {
    private var currentProcess: Session? = null

    override fun exec(command: String?, timeout: Int): Process {
      val session = ssh.startSession()
      currentProcess = session
      val channel = session.exec(command)
      return HeadlessProcess(channel, timeout.toLong())
    }

    override fun disconnect() {
      currentProcess?.close()
      currentProcess = null
      ssh.close()
    }
  }

  private class HeadlessProcess(
    private val command: Session.Command,
    private val timeout: Long,
  ) : Process() {
    override fun waitFor(): Int {
      command.join(timeout, TimeUnit.SECONDS)
      command.close()
      return exitValue()
    }

    override fun destroy() = command.close()

    override fun getOutputStream() = command.outputStream

    override fun getErrorStream() = command.errorStream

    override fun exitValue(): Int = command.exitStatus

    override fun getInputStream() = command.inputStream
  }

  companion object {
    private const val CONNECT_TIMEOUT = 10
    private const val WORK_NAME = "passkey_auto_sync"

    fun enqueue(context: Context) {
      val workRequest = OneTimeWorkRequestBuilder<PasskeySyncWorker>().build()
      WorkManager.getInstance(context)
        .enqueueUniqueWork(
          WORK_NAME,
          ExistingWorkPolicy.REPLACE,
          workRequest,
        )
    }
  }

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface PasskeySyncWorkerEntryPoint {
    fun gitSettings(): GitSettings

    fun dispatcherProvider(): DispatcherProvider

    fun passkeyRepositoryState(): PasskeyRepositoryState

    fun generationProvider(): RepositoryGenerationProvider

    @GitSecrets fun gitSecrets(): SharedPreferences
  }
}
