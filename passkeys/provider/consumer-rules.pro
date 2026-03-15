# Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
# SPDX-License-Identifier: GPL-3.0-only

# Keep WebAuthn model classes for serialization
-keep class app.passwordstore.passkeys.provider.** { *; }
-keep class app.passwordstore.passkeys.model.** { *; }
-keep class app.passwordstore.passkeys.crypto.** { *; }
-keep class app.passwordstore.passkeys.storage.** { *; }