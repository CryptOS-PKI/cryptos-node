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

It signs an unsigned ISO the same way, so you can install from a signed ISO
without rebuilding it; see [Sign an ISO](#sign-an-iso).

## Before you start

- An unsigned CryptOS UKI or ISO, for example a release asset, or
  `build/out/cryptos-amd64.uki.unsigned` or
  `build/out/cryptos-amd64-vmware-unsigned-<build>.iso` from a
  cryptos-appliance build.
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

## Sign an ISO

Give `--image` an ISO instead of a UKI. The command tells the two apart by
their content, not their names. It needs no root, no `xorriso` and no rebuild.

1. Sign it:

   ```sh
   cryptosctl image sign \
     --image cryptos-amd64-vmware-unsigned-v0.1.0.iso \
     --key release.key \
     --cert release.crt
   ```

   It signs the UKI inside the ISO exactly as it signs a UKI on its own, then
   writes the signed UKI back over every copy the ISO carries:

   - `EFI/BOOT/BOOTX64.EFI` in the EFI boot image, which the firmware boots;
   - `/cryptos.uki`, which the installer copies to the disk it installs.

   It writes three files. With no `--out`, the signed ISO is the input name
   without `-unsigned` (`cryptos-amd64-vmware-v0.1.0.iso`); an input with any
   other name gets `.signed.iso`. Beside the ISO it writes the signed UKI,
   named like the ISO with `.uki` in place of `.iso`
   (`cryptos-amd64-vmware-v0.1.0.uki`), and that UKI's release signature
   (`cryptos-amd64-vmware-v0.1.0.uki.sig`). The command prints each place in
   the ISO it signed, the paths and the SHA-256 of the ISO and the UKI.

   Before it writes anything, it reads the new ISO back, checks that every
   copy is the signed UKI, and checks the signature and the anchor.

2. Optionally, check the Secure Boot signature on the UKI written beside the
   ISO, the same bytes as the copies inside it:

   ```sh
   sbverify --cert release.crt cryptos-amd64-vmware-v0.1.0.uki
   ```

3. Install a node from the signed ISO. Keep the signed `.uki` and `.sig`:
   they are what you stage onto a node, and later ISOs or UKIs you sign with
   the same key upgrade every node installed from this one.

> [!CAUTION]
> The EFI boot image inside the ISO keeps its size. A cryptos-appliance build
> leaves 2 MiB free in it, far more than signing adds, but an ISO built some
> other way with no free space is refused, and nothing is written.

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
