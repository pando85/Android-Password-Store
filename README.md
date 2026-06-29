# Password Store (pando85 fork)

[![CI](https://github.com/pando85/Android-Password-Store/actions/workflows/pull_request.yml/badge.svg)](https://github.com/pando85/Android-Password-Store/actions)
[![Release](https://github.com/pando85/Android-Password-Store/actions/workflows/release.yml/badge.svg)](https://github.com/pando85/Android-Password-Store/releases)

## Download

- [GitHub Releases](https://github.com/pando85/Android-Password-Store/releases)

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

## How-To: Transfer a PGP key to Password Store securely

### From GPG keyring
````bash
gpg --armor --gen-random 1 24 # generate a strong random password; use it in the next step
gpg --armor --export-secret-keys <ID of key used for pass> | gpg --armor --symmetric --output myKeyForPass.sec.asc
````
File `myKeyForPass.sec.asc` can be directly imported into Password Store via Settings → PGP Settings → Key Manager → <kbd>+</kbd>; enter the password from the first step when asked for the backup code.

### From OpenKeychain
1. In the main app window, select the key that you use for `pass`/Password Store from the "My Keys" list.
2. In the window that appears, tap the three-dot menu in the top right corner and select "Backup key".
3. Write down the backup code, then save the backup file to your phone.
4. Import this backup file into Password Store by navigating to Settings → PGP Settings → Key Manager → <kbd>+</kbd>, and enter the backup code when prompted.

## Contributing

This fork adds passkey/WebAuthn support with passless compatibility. See [CHANGELOG](CHANGELOG.md) and [Release process](RELEASE.md).

## Donations

If you wish to sponsor the original author, financial contributions can be made through the following platforms

- [GitHub Sponsors](https://github.com/sponsors/android-password-store)
- [OpenCollective](https://opencollective.com/android-password-store)
