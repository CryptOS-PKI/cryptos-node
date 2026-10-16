# Signing an image with your own key

The CryptOS release assets are built unsigned, and they carry no upgrade
anchor. An upgrade anchor is the certificate a node checks an incoming image
against before it writes the image to its ESP. A node installed from an
unsigned asset as-is serves the image upgrade calls (`image stage`,
`image rollback`, `image activate`) as unavailable.

`cryptosctl image sign` fixes that on your workstation. It needs no rebuild, no
root and no other tools, and it runs on Linux and macOS. With your Secure Boot
key and certificate it:

- adds your certificate to the image as its upgrade anchor;
- Authenticode-signs the image for Secure Boot, the same form `sbsign` writes;
- writes the detached release signature that `image stage` sends, beside the
  image as `<out>.sig`.

A node installed from an image you signed this way takes signed in-place
upgrades: any later image you sign with the same key can be staged onto it
with `cryptosctl image stage`.

## Before you start

- An unsigned CryptOS UKI, for example a release asset or
  `build/out/cryptos-amd64.uki.unsigned` from a cryptos-appliance build.
- Your Secure Boot signing key as an unencrypted RSA PEM file (PKCS#1 or
  PKCS#8), and its certificate as PEM or DER. This is the certificate
  enrolled in your machines' Secure Boot db. Keep the key file readable by you
  only.
- A `cryptosctl` built from this repo (`task build` writes `bin/cryptosctl`).

## Sign the image

1. Sign it:

   ```sh
   cryptosctl image sign \
     --image cryptos-amd64.uki.unsigned \
     --key release.key \
     --cert release.crt
   ```

   With no `--out`, the signed image goes next to the input without its
   `.unsigned` suffix (`cryptos-amd64.uki`); an input with any other name gets
   `.signed.uki`. The release signature is written as `<out>.sig`. The command
   prints both paths, the image's SHA-256, and the anchor certificate's
   subject and SHA-256 fingerprint.

2. Optionally, check the Secure Boot signature on a Linux host that has
   `sbsigntools`:

   ```sh
   sbverify --cert release.crt cryptos-amd64.uki
   ```

3. Install a new node from the signed image, or stage it onto a node that
   already trusts this key:

   ```sh
   cryptosctl --endpoint pki-root.example:443 image stage --image cryptos-amd64.uki
   ```

   `image stage` picks up `cryptos-amd64.uki.sig` by default.

## What it changes in the image

- **The anchor.** A small uncompressed cpio archive holding
  `upgrade-anchor.der` (your certificate, DER) is appended to the UKI's
  `.initrd`. The kernel unpacks it as `/upgrade-anchor.der`, and the
  initramfs hands it to init. Because it is part of `.initrd`, it is measured
  into PCR 11 and covered by the Secure Boot signature, the same as the
  kernel.
- **The layout.** The sections after `.initrd` move up to make room. The
  systemd-stub sections before it keep their bytes and addresses.
- **The signature.** Any existing Authenticode signature is replaced by yours.

Signing an already signed image again appends a second anchor; the last one
wins, so the image then trusts only the new key.

## Which anchor a node uses

A node takes its anchor from the image it is running. A sign-time anchor (from
`image sign`) wins over a build-time one (stamped in by a cryptos-appliance
build with `SB_CERT` set). An image with neither serves the upgrade calls as
unavailable. To move a node onto a different key, reinstall it from an image
signed with the new key.
