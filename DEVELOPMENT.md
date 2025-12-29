# Development Guide

## Prerequisites

Before building and installing the app, ensure your Android device is set up for development:

1. **Enable Developer Options** on your Android device:

   - Go to **Settings → About Phone**
   - Tap "Build Number" 7 times

2. **Enable USB Debugging**:

   - Go to **Settings → Developer Options → USB Debugging → On**

3. **Verify device connection**:

   ```bash
   adb devices
   ```

   This should show your device listed.

---

## Build & Install

### Option 1: Using Gradle (Recommended)

Connect your Android device via USB with USB debugging enabled, then run:

```bash
./gradlew :app:installFreeDebug
```

This builds and installs in one step.

### Option 2: Manual APK Install

1. **Build the APK**:

   ```bash
   ./gradlew :app:assembleDebug
   ```

2. **Find the APK**:

   ```text
   app/build/outputs/apk/free/debug/app-free-debug.apk
   ```

3. **Install via ADB**:

   ```bash
   adb install app/build/outputs/apk/free/debug/app-free-debug.apk
   ```

   Or transfer the APK to your device and install manually.

---

## Testing Passkeys (Android 14+ only)

After installing:

1. **Enable Password Store as a Credential Provider**:

   - Go to **Settings → Passwords & accounts → Credential providers**
   - Enable "Password Store Passkeys"

2. **Test passkey creation**:
   - Visit [webauthn.io](https://webauthn.io) in Chrome
   - Register a new passkey
   - Select Password Store when prompted
