/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class AutofillPreferencesTest {

  @Test
  fun nullOrEmptyFallsBackToRoot() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory(null))
    assertNull(AutofillPreferences.sanitizeSaveDirectory(""))
    assertNull(AutofillPreferences.sanitizeSaveDirectory("   "))
  }

  @Test
  fun acceptsSingleSegment() {
    assertEquals("www", AutofillPreferences.sanitizeSaveDirectory("www"))
  }

  @Test
  fun acceptsNestedSegments() {
    assertEquals("www/personal", AutofillPreferences.sanitizeSaveDirectory("www/personal"))
  }

  @Test
  fun rejectsAbsolutePath() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory("/www"))
  }

  @Test
  fun rejectsLeadingTraversal() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory("../www"))
  }

  @Test
  fun rejectsEmbeddedTraversal() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory("www/../personal"))
  }

  @Test
  fun rejectsCurrentDirectoryComponent() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory("."))
    assertNull(AutofillPreferences.sanitizeSaveDirectory("www/./personal"))
  }

  @Test
  fun rejectsEmptyPathComponents() {
    assertNull(AutofillPreferences.sanitizeSaveDirectory("www//personal"))
    assertNull(AutofillPreferences.sanitizeSaveDirectory("www/"))
  }
}
