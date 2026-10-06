# cryptos-node 🧠

> 🔐 The OS / engine for [CryptOS-PKI](https://github.com/CryptOS-PKI) — an immutable, API-driven, high-assurance PKI operating system in the Talos Linux tradition.

Builds a signed Unified Kernel Image (UKI): hardened kernel + Go-based PID 1 + read-only SquashFS rootfs + TPM-unsealed encrypted state partition. A single image boots into a Root, Intermediate, or Issuing CA role based on its machine config. No SSH, no shell, no interactive access. Private keys are TPM-bound and never live on disk in the clear.

> [!WARNING]
> 🚧 **Pre-1.0: any release can change fundamentally.** CryptOS is pre-1.0. Until v1.0.0, any release may change configuration, APIs, on-disk and state formats, trust setup, and upgrade paths, sometimes with no migration path. If you run it in production, you accept that risk. Read [each release's upgrade notes](https://github.com/CryptOS-PKI/cryptos-node/releases) before you upgrade.

## ✨ Architecture at a glance

- 🪨 **Immutable rootfs** — SquashFS, read-only. Persistent state only on the encrypted partition, unsealed by the local TPM.
- 🔑 **TPM-bound identity** — CA private keys are created inside the TPM and never leave it. ECDSA P-384 for Roots, P-256 for Issuing CAs. An RSA-3072 or RSA-4096 CA key is held in the TPM the same way when the TPM implements that size; otherwise key creation refuses it rather than fall back.
- 🚫 **No interactive access** — no SSH, no shell, no usernames/passwords. **No web frontend in the image either.** Management is `cryptosctl` over mTLS gRPC, or the Fleet Manager (which talks the same mTLS gRPC).
- 📐 **RFC-strict** — TLS 1.3 (RFC 8446), X.509 (RFC 5280), and every protocol adapter follows its RFC to the letter.
- 📜 **Declarative** — machine config in YAML (`apiVersion: cryptos.dev/v1alpha1`), applied via `ApplyConfig`. No click-ops.
- 🧪 **Stdlib-only on the cert path** — `crypto/x509`, `crypto/tls`, `crypto/ecdsa`, `crypto/rand`, `golang.org/x/crypto`. No `cfssl`, no `smallstep`, no PKI wrappers — ever.

## 📂 Layout

This repo is the PKI engine: the node API, PID 1, the management CLI and the
bare-metal installer. The signed boot image that runs them — kernel, SquashFS,
UKI assembly, Secure Boot signing, and the QEMU test suites — is built in
[`cryptos-appliance`](https://github.com/CryptOS-PKI/cryptos-appliance), which
pins this repo and builds its binaries by import path.

```
proto/cryptos/node/v1/ # the node API (cryptos.node.v1) this OS serves
gen/go/cryptos/node/v1/ # generated Go stubs (package nodev1); `task generate`, never hand-edited
cmd/
  init/             # PID 1 binary; becomes /init in the SquashFS
  cryptosctl/       # operator CLI (the only management surface on a standalone node)
  cryptos-install/  # bare-metal disk installer (GPT + ESP + UKI)
internal/
  init/             # supervisor + boot bring-up
    netlink/        # NIC bring-up via rtnetlink
    mounts/         # early mount sequence
  timesync/         # client-only SNTPv4: boot step, periodic slew, clock floor
  tpm/              # go-tpm wrapper, SRK provisioning, crypto.Signer impl
  ca/               # RFC 5280 cert template builder
  ceremony/         # first-boot ceremony state machine
  storage/
    luks/           # TPM-sealed LUKS2 open/format
    etcd/           # embedded etcd config + schema
  grpc/             # mTLS gRPC server, RPC handlers
  node/             # typed etcd state layer + gRPC Identity/Status/Config providers
  install/          # bare-metal disk provisioning (partition plan + UKI install)
  audit/            # hash-chained audit log
  config/           # machine config parser + validator
  bootstrap/        # bootstrap admin cert loading + first-ceremony rotation
scripts/buildinfo.sh # build-identity ldflags for `task build` (see cryptos-appliance for the image's own copy)
test/kind/          # kind + cert-manager ACME end-to-end harness (task e2e:kind)
testdata/configs/   # sample machine configs
```

## 🛠️ Build + run (dev loop)

Requires Go 1.26.8+ (the `go` line in `go.mod`; an older local Go downloads that toolchain on first use), [`go-task`](https://taskfile.dev), `golangci-lint`, `golic`, [`buf`](https://buf.build) (proto lint and codegen), and (for the TPM-held RSA CA test) `swtpm`. `task test` runs that test against `swtpm` when it is installed, because the in-process TPM simulator implements RSA-2048 only; without `swtpm` it skips locally and fails in CI.

```bash
task ci          # fmt + proto lint + generated-code check + lint + vet + test + build
task generate    # regenerate gen/go from proto/ with the pinned plugins (task tools)
task build       # produces bin/init, bin/cryptosctl and bin/cryptos-install, stamped with the build identity
task license     # re-inject Apache 2.0 headers via golic
task e2e:kind    # Linux + docker: cert-manager in kind gets a certificate over ACME
```

`task e2e:kind` builds a Root and an ACME-serving Intermediate in-process (software keys, no TPM), stands up a kind cluster with cert-manager and Contour, and checks that a `Certificate` goes Ready with a chain to the root and renews to a new serial. It downloads pinned, checksum-checked kind, kubectl and manifests ([`test/kind/versions.env`](test/kind/versions.env)), needs sudo once to add a `/etc/hosts` line for the test name, and skips when docker isn't available.

`bin/cryptosctl version` prints the version, commit, and build date the binary was built from (`git describe --tags --always --dirty`; see [`scripts/buildinfo.sh`](scripts/buildinfo.sh)); pass `--endpoint` to also show the node's version.

### The boot image

This repo builds no bootable image. The hardened kernel, SquashFS rootfs, UKI assembly, Secure Boot signing, the installer ISO and the QEMU + `swtpm` integration suites all live in [`cryptos-appliance`](https://github.com/CryptOS-PKI/cryptos-appliance), which requires this module at a pinned version and builds `init`, `cryptosctl` and the console by import path. See that repo's README and `docs/secure-boot.md` for building, signing and Secure Boot key custody.

## 🤖 Continuous integration

GitHub Actions:

- **`ci-go`** ([`ci-go.yml`](.github/workflows/ci-go.yml)) — `task ci` (format, proto lint, generated-code check, lint, vet, test, build) on every pull request + push to `main`, on a GitHub-hosted Linux runner, with `swtpm` installed for the TPM-held RSA CA test. Draft pull requests are skipped; CI runs when the PR is marked ready.

After a stacked pull request is retargeted onto `main`, CI starts on its next push, or when it is toggled to draft and back to ready.

- **`ci-kind-acme`** ([`ci-kind-acme.yml`](.github/workflows/ci-kind-acme.yml)) — `test/kind/run.sh` (the `task e2e:kind` harness) on pull requests that touch the ACME, config, node or e2e code, on a GitHub-hosted runner. Drafts are skipped, and it isn't a required check.

`cryptos-appliance` runs its own `ci-image` and `ci-e2e-image` against the image it builds from this repo.

## 🔑 Management surfaces

A CA node has exactly two ways to be managed:

| | When | What |
|---|---|---|
| `cryptosctl` | Always — and the **only** option on a standalone (unlinked) node. | Local UNIX socket on the node for break-glass; remote mTLS gRPC for everything else. |
| Fleet Manager | Optional. When you want a web UI or multi-node view. | The `manager/` backend serves the `web/` frontend; talks to nodes via the same mTLS gRPC API. |

There is no third surface. The OS image ships no web frontend — neither source nor compiled — by design.

Remote `cryptosctl` checks the node's management certificate against `--trust`. Before the node has a CA, that certificate is self-signed and regenerated on every boot, so you pin it: the console shows its SHA-256, and `cryptosctl trust fetch --expect-sha256 <fingerprint>` saves the pin only when it matches. Once the node has a CA, the certificate is signed by it and `--trust` is your root certificate, which survives reboots. [`docs/management-trust.md`](docs/management-trust.md) covers both.

An intermediate can get a fresh certificate for the key it already holds, for example one that carries CRL, OCSP and caIssuers pointers after the parent's `revocation_base_url` was set: `cryptosctl ca get-renewal-csr`, `ca sign-subordinate` on the parent, then `ca submit-renewed-cert`. No re-key and no reboot. [`docs/subordinate-recertify.md`](docs/subordinate-recertify.md) has the procedure and the openssl checks.

Every issued certificate comes from a named profile in the machine config. [`docs/certificate-profiles.md`](docs/certificate-profiles.md) is the field reference. It also covers how a certificate's validity is capped at the issuing CA's own notAfter (or refused, with `validity_policy: reject`), and the warnings `cryptosctl` prints when that happens.

A node keeps every certificate it issues. `cryptosctl ca list-issued` lists them, `ca get-issued --serial <hex>` prints one as PEM with its chain up to the root and its status (`valid`, `revoked` or `expired`), and `ca revoke` revokes one. [`docs/issued-certificates.md`](docs/issued-certificates.md) covers all three.

Every call to a node's API, except the status polling from the console and the Fleet Manager, is recorded in its hash-chained audit log. `cryptosctl audit list` reads it, with time, call and actor filters, and `audit verify` checks the signatures and the chain and exits non-zero when it is broken. [`docs/audit-log.md`](docs/audit-log.md) covers both.

A node keeps its clock in sync over SNTP with the servers in `network.ntp_servers` (or its DHCP lease), and refuses to sign certificates until the first sync when a time source is configured. CRL and OCSP are never held up. [`docs/time-sync.md`](docs/time-sync.md) covers the servers, the signing gate and its `pki.allow_unsynced_clock` override, and the `Clock:` status line.

Issuing LDAPS and KDC certificates to Active Directory domain controllers, including `certreq` on Server Core, is covered in [`docs/active-directory.md`](docs/active-directory.md). [`docs/active-directory-root-gpo.md`](docs/active-directory-root-gpo.md) distributes the root to domain members with Group Policy.

Network devices that cannot run ACME, such as Cisco IOS and IOS-XE trustpoints, enrol over SCEP (RFC 8894): each initial enrolment is authorized by a one-time challenge from `cryptosctl scep challenge mint`, and renewal by the device's current certificate. [`docs/scep.md`](docs/scep.md) covers switching it on, the per-profile key floor, the RA certificate and the approval queue.

### Rebooting or powering off a node

Most `config apply` changes report `requires_reboot=true`. Restart the node through its orderly shutdown rather than a hypervisor hard reset:

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

```sh
cryptosctl --endpoint pki-root.example:443 reboot --confirm "Example Root CA G1"
cryptosctl --endpoint pki-root.example:443 reboot --confirm "Example Root CA G1" --power-off
```

`--confirm` must be the node's CA common name, and over mTLS the call needs the bootstrap admin client certificate. The node replies, then stops its listeners, closes etcd and the audit log, unmounts and locks the state volume, and restarts (or powers off). A hard reset skips all of that. The management certificate gets a new key on every boot, so refresh a pinned `--trust` afterwards; a `--trust` that holds the CA keeps working.

The same orderly shutdown also runs, without the API, when:

- the ACPI power button is pressed (a hypervisor guest shutdown that goes through ACPI, such as `virsh shutdown`). The node **powers off**.
- Ctrl-Alt-Del reaches the console (for example, the vSphere console's "Send Ctrl+Alt+Delete"; the VMware image carries the PS/2 keyboard driver for this). The node **reboots**.
- PID 1 receives `SIGTERM` or `SIGINT`. The node **reboots**.

The image ships no guest tools, so a vSphere "Shut Down Guest OS" or "Restart Guest OS" request is not available. Use `cryptosctl reboot`, or the console's Ctrl+Alt+Delete.

## 🚦 Status

**Pre-alpha.** Phase 1 scaffolding has landed; subsystem implementation is in progress.

1. 🪨 **Phase 1 — Core OS + single-node Root CA MVP.** Boot a UKI in QEMU + `swtpm`, generate a TPM-resident ECDSA P-384 Root key, self-sign an RFC 5280-strict Root cert, validate via `cryptosctl`.
2. 🔌 **Phase 2 — Role-aware API + protocol adapters + Fleet Manager.** Root / Intermediate / Issuing role split, ACME / SCEP / EST / WSTEP / RFC 3161 / OCSP / CRL.
3. 🛡️ **Phase 3 — Pool, HA, extensions, isolation, recovery.** 2-node HA pairs (Infoblox-style failover, VRRPv3 VIP), multi-Root topology (configurable depth, default cap 3), Fleet Manager linkage protocol, Talos-style signed late-binding extensions, disaster-recovery escrow.

## 📡 Node API

The gRPC API this OS serves is defined here, in [`proto/cryptos/node/v1`](proto/cryptos/node/v1) (package `cryptos.node.v1`). The Go stubs live under [`gen/go/cryptos/node/v1`](gen/go/cryptos/node/v1) (import `github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1`, package `nodev1`), and the Fleet Manager imports them from there. Change a `.proto`, run `task generate`, and commit the regenerated tree in the same change; `task ci` fails when `gen/` is stale. `task proto:breaking` checks a change against `main`.

## 🧭 Companion repos

- 🛰️ [`manager`](https://github.com/CryptOS-PKI/manager) — Fleet Manager backend (optional).
- 🎨 [`web`](https://github.com/CryptOS-PKI/web) — Fleet Manager web frontend (optional, served by `manager/`).

## 🙏 Acknowledgements

CryptOS was originally written by [@Bugs5382](https://github.com/Bugs5382).

## 📄 License

[Apache License 2.0](LICENSE). Copyright The CryptOS Authors.
