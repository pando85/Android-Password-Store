/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git.operation

import androidx.appcompat.app.AppCompatActivity
import java.util.Date
import org.eclipse.jgit.api.GitCommand

/**
 * Run an aggressive garbage collection job on the repository, expiring every loose object to
 * achieve the best compression.
 */
class GcOperation(callingActivity: AppCompatActivity) : GitOperation(callingActivity) {

  override val requiresAuth: Boolean = false
  override val commands: Array<GitCommand<out Any>> =
    arrayOf(git.gc().setAggressive(true).setExpire(null as Date?))
}
