2fa is a two-factor authentication agent.

Usage:

    cargo install --path .

    2fa --add [-7] [-8] [--hotp] [--key KEY] name
    2fa --list
    2fa [--clip] [--key KEY] name

`2fa --add name` adds a new key to the 2fa keychain with the given name. It
prints a prompt to standard error and reads a two-factor key from standard
input. Two-factor keys are short case-insensitive strings of letters A-Z and
digits 2-7.

By default the new key generates time-based (TOTP) authentication codes; the
`--hotp` flag makes the new key generate counter-based (HOTP) codes instead.

By default the new key generates 6-digit codes; the `-7` and `-8` flags select
7- and 8-digit codes instead.

`2fa --list` lists the names of all the keys in the keychain.

`2fa name` prints a two-factor authentication code from the key with the
given name. If `--clip` is specified, `2fa` also copies the code to the system
clipboard.

With no arguments, `2fa` prints two-factor authentication codes from all
known time-based keys.

The default time-based authentication codes are derived from a hash of the
key and the current time, so it is important that the system clock have at
least one-minute accuracy.

The keychain is stored in the text file `$HOME/.2fa`. When `--key` is
provided, 2FA secrets are encrypted at rest with AES-256-GCM using the
supplied passphrase; otherwise secrets are stored in plaintext.

## Example

During GitHub 2FA setup, at the "Scan this barcode with your app" step,
click the "enter this text code instead" link. A window pops up showing
"your two-factor secret," a short string of letters and digits.

Add it to 2fa under the name github, typing the secret at the prompt:

    $ 2fa --add github
    2fa key for github: nzxxiidbebvwk6jb
    $

Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:

    $ 2fa github
    268346
    $

Or to type less:

    $ 2fa
    268346	github
    $

## Encrypted storage

To protect your 2FA secrets at rest, pass `--key` whenever you add or read keys:

    $ 2fa --add --key mypassphrase github
    2fa key for github: nzxxiidbebvwk6jb
    $

    $ 2fa --key mypassphrase github
    268346
    $

The secret is encrypted with AES-256-GCM. The key is derived from the
supplied passphrase using SHA-256. The same `--key` value must be provided
every time you read or add an encrypted entry.
