# Subordinating VMware VMCA under a CryptOS CA

vCenter's built-in CA (VMCA) can run as a subordinate issuing CA under a CryptOS
root, so everything it issues for vSphere and ESXi chains to your root instead of
a self-signed VMCA root. VMCA keeps issuing; only its own certificate changes.

The same shape applies to Microsoft AD CS, which also generates its own key and
offers no algorithm choice.

## The one requirement that decides everything: RSA end to end

vSphere **does not accept ECDSA signatures**. From *Certificate Requirements for
Different Solution Paths* (vSphere 8.0, unchanged in 9.0):

> vSphere deploys only RSA certificates for server authentication and does not
> support generating ECDSA certificates.

A certificate's signature algorithm is a property of its **issuer's** key, not
its own. So it is not enough that VMCA's request is RSA — the CryptOS CA signing
it must hold an RSA key, and so must every CA above it. An RSA intermediate
under an ECDSA root does not work: the intermediate's own certificate carries an
`ecdsa-with-SHA384` signature and appears in the chain vCenter verifies.

> [!WARNING]
> **This fails silently at signing time.** CryptOS will happily certify an RSA
> subject key from an ECDSA CA and hand you a certificate; vCenter refuses it at
> import, after `certificate-manager` has started. `TestVMCASubordination_UnderAnECDSACARejected`
> exists to pin that behaviour so it is not rediscovered the hard way.

An ECDSA-rooted fleet therefore needs a **separate RSA hierarchy** for this, not
a re-key of the existing one.

## What the CA must be configured with

The signing node needs an RSA CA key, a revocation base URL, and a CA profile:

```yaml
pki:
  root_key_alg: RSA-3072          # or RSA-4096. RSA-2048 is rejected: the CA
                                  # will not certify a subject key below 3072.
  revocation_base_url: http://pki-inter.example
  profiles:
    - name: platform-sub-ca
      key_alg: RSA-3072           # required by validation; governs keys this
                                  # node generates, not the ones it certifies,
                                  # so VMCA's own key is fine
      validity_days: 1825         # capped at the signing CA's own notAfter
      basic_constraints:
        is_ca: true
        path_len: 0               # VMCA may not create sub-CAs of its own
      key_usage: [digital_signature, cert_sign, crl_sign]
      # ext_key_usage: leave unset (or [server_auth] only)
      # sans: leave unset (or at most one dns entry)
```

`cert_sign` and `crl_sign` are both required — vCenter states CRL signing must be
enabled. The accepted `key_usage` names are `digital_signature`, `cert_sign`,
`crl_sign`, `key_encipherment` and `key_agreement`; any other name fails config
validation. Extended key usage must be empty or `server_auth` only.

The subject of the issued certificate comes from VMCA's CSR, but every extension
comes from the profile, including subject alternative names: whatever is in the
profile's `sans` block is stamped onto the VMCA certificate, and SANs in the CSR
are ignored. vCenter rejects a VMCA signing certificate with more than one DNS
name, so leave `sans` unset, or give it at most one `dns` entry and nothing else.

`path_len: 0` is the requested value. If the signing CA is itself
pathLen-constrained, the node clamps the requested value to the budget its own
certificate leaves, so it can only get tighter.

`validity_days` doesn't need to be fitted to the signing CA by hand. The node
caps the VMCA certificate at its own notAfter, because a VMCA certificate that
outlived its issuer would fail chain validation from the day the issuer expired.
When the cap applies, `sign-subordinate` prints a warning on stderr, for example
`WARNING: requested validity ends 2031-09-22; capped to issuer notAfter
2030-03-01`, and the audit log records both dates. `cryptosctl config apply` warns
ahead of time when a profile's `validity_days` already runs past the CA. Set
`validity_policy: reject` on the profile to refuse instead of capping. See
[`certificate-profiles.md`](certificate-profiles.md#validity-and-the-issuing-cas-notafter).

> [!IMPORTANT]
> **Set `revocation_base_url` before signing.** It is what stamps revocation
> pointers onto issued certificates: a CRL distribution point at `<base>/crl`, an
> AIA OCSP pointer at `<base>/ocsp`, and an AIA caIssuers pointer at
> `<base>/ca.cer`, where the node serves its own CA certificate (DER,
> `application/pkix-cert`) so a client that holds only the root can fetch the
> intermediate and build the chain. With it empty, the VMCA certificate is issued
> with none of them and nothing can check whether it has been revoked;
> a certificate already issued cannot gain them later without being re-signed. When
> it is set, signing fails closed if the node's revocation preflight is not passing
> (the URL does not resolve, or `/crl`, `/ocsp` or `/ca.cer` is unreachable), unless
> `allow_unverified_revocation_url: true` is set.

> [!IMPORTANT]
> **Give the node a resolver when the URL names a host.** The preflight resolves
> the `revocation_base_url` host from the node itself, so the node needs DNS
> servers that resolve that name. Declare them in the machine config:

```yaml
network:
  interface: eth0
  address: 10.0.0.10/24
  gateway: 10.0.0.1
  nameservers: [10.0.0.53, 10.0.1.53]   # IPv4 literals, at most 3, in order
  search: [example.org]                 # optional, at most 6
```

With `nameservers` empty the node uses the DNS servers and domain from the
kernel's DHCP lease, if it got one. That is best effort: the node replaces the
lease with its static address, and the lease's servers may not be the ones that
resolve the CA's own name, so set `nameservers` explicitly on a production CA.
`cryptosctl config apply` warns when `revocation_base_url` names a host and
`nameservers` is empty. The resolver is written at boot, so a change takes
effect on the next reboot. It does not relax the preflight: if the name still
does not resolve, or `/crl`, `/ocsp` or `/ca.cer` does not answer, issuance stays blocked.

`cryptosctl status` shows both. The `Revocation:` line gives the preflight state
(`OK`, `FAILING`, `PENDING` before the first check, or `NOT_CONFIGURED`), the
URL, when it was last checked, and the last error while failing, which names
the step that failed: resolving the host, or `/crl`, `/ocsp` or `/ca.cer` not
answering. The `DNS:` line
gives where the resolver came from (`MACHINE_CONFIG`, `DHCP_LEASE`, or `NONE`)
and the nameservers and search list in use.

An RSA CA key works in every `state_key.mode`. With `tpm` the key is created
and held in the TPM, like the ECDSA key. The TPM 2.0 spec only requires a TPM
to implement RSA-2048, though, and many parts stop there.

> [!CAUTION]
> On a `tpm` node, check the TPM's datasheet for the RSA size you configure
> before you run the ceremony. If the TPM lacks it, the ceremony stops with
> `FailedPrecondition` naming the algorithm, before any key is created, and you
> can run it again with another `root_key_alg`. An intermediate or issuing
> node makes its key at first boot instead, and its boot stops on the same
> error. It never falls back to a software key or a smaller size. The boot log's `init: TPM capabilities:` line
> lists the RSA sizes the TPM accepted. If yours is missing, use a node whose TPM
> has it, or the `nodeid` or `kms` mode, where the key is software-held. On a
> hardware TPM, generating an RSA key can take tens of seconds.

## The procedure

**1. Generate the request on vCenter.** Put VMCA into intermediate CA mode and
have it emit its CSR. Copy the CSR off the appliance, then check its key size
before going further:

> [!IMPORTANT]
> Do not assume the key size; the tooling on the appliance can produce a
> smaller key depending on how it is invoked.

**Linux / macOS**

```bash
openssl req -in vmca.csr -noout -text | grep Public-Key
```

**Windows (PowerShell)**

```powershell
openssl req -in vmca.csr -noout -text | Select-String -CaseSensitive Public-Key
```

> [!TIP]
> The output is the size of VMCA's key. Expected output: `Public-Key: (3072 bit)`
> or larger.
>
> The node refuses any RSA subject key below 3072 bits, so anything smaller than
> `(3072 bit)` is rejected at signing. Stop and generate a new request on
> vCenter if the key is smaller.

**2. Sign it with the CryptOS CA.** From an operator workstation with an admin
credential for the signing node. The signing node has its CA, so its
management certificate is signed by that CA and your root verifies it (see
[`management-trust.md`](management-trust.md)). The node console confirms it
with the **Mgmt cert** line reading **CA-signed, trust the CA**.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

```sh
cryptosctl ca sign-subordinate \
  --endpoint 192.0.2.10:443 \
  --identity admin.crt --identity-key admin.key \
  --trust root.pem \
  --csr vmca.csr \
  --profile platform-sub-ca > vmca-chain.pem
```

`sign-subordinate` is a subcommand of `ca`. `--endpoint`, `--identity`,
`--identity-key` and `--trust` are the global connection flags: the node's
`host:port`, the admin client certificate and its key, and the root the
node's management certificate chains to. Address the node by its IP or by a
name in its `pki.est.hostnames`; those are the names its management certificate
carries. If you connect through another DNS name, add `--server-name` with the
IP. There is no `--node` flag. `--csr` (PEM or DER) and `--profile` are both
required. The profile must be a CA profile (`is_ca: true`) defined on the
signing node.

If the call fails with `certificate signed by unknown authority`, `root.pem` is
not the root the signing node chains to. Either way, step 3 is the real check:
a certificate that verifies against your root came from your CA. See
[`management-trust.md`](management-trust.md) for the details.

> [!IMPORTANT]
> The output is leaf-first: the new VMCA certificate followed by the certificate of
> the CA that signed it. **The root is not included.** When the signing node is an
> intermediate, the output is VMCA plus that intermediate and nothing above it.
> `certificate-manager` needs the full chain, so append the rest of the chain up to
> and including the root yourself:

**Linux / macOS**

```bash
cat vmca-chain.pem root.pem > vmca-fullchain.pem
```

**Windows (PowerShell)**

```powershell
Get-Content vmca-chain.pem, root.pem | Set-Content vmca-fullchain.pem -Encoding ascii
```

Under a deeper hierarchy, append each missing CA certificate in order, leaf to
root, before the root.

**3. Verify before importing.** Importing is the disruptive step, so check the
result first:

**Linux / macOS**

```bash
# the VMCA certificate (the first one in the file)
openssl x509 -in vmca-fullchain.pem -noout -text | grep -E 'Signature Algorithm|Not After|CA:|Key Usage|CRL Distribution|OCSP|CA Issuers' -A1
# the signature algorithm of every certificate in the chain
openssl crl2pkcs7 -nocrl -certfile vmca-fullchain.pem | openssl pkcs7 -print_certs -text -noout | grep 'Signature Algorithm'
# the chain verifies to your root
openssl verify -CAfile root.pem -untrusted vmca-chain.pem vmca-chain.pem
```

**Windows (PowerShell)**

```powershell
# the VMCA certificate (the first one in the file)
openssl x509 -in vmca-fullchain.pem -noout -text | Select-String -CaseSensitive -Pattern 'Signature Algorithm|Not After|CA:|Key Usage|CRL Distribution|OCSP|CA Issuers' -Context 0,1
# the signature algorithm of every certificate in the chain
openssl crl2pkcs7 -nocrl -certfile vmca-fullchain.pem | openssl pkcs7 -print_certs -text -noout | Select-String -CaseSensitive 'Signature Algorithm'
# the chain verifies to your root
openssl verify -CAfile root.pem -untrusted vmca-chain.pem vmca-chain.pem
```

> [!TIP]
> Expect a `sha256WithRSAEncryption` or `sha384WithRSAEncryption` signature,
> a `Not After` no later than the signing CA's own,
> `CA:TRUE, pathlen:0`, both `Certificate Sign` and `CRL Sign`, and the CRL
> distribution point, OCSP URL and CA Issuers URL under your `revocation_base_url`. An
> `ecdsa-with-SHA384` signature on any certificate in the chain means the hierarchy
> is not RSA end to end and vCenter will refuse the import.

> [!WARNING]
> vCenter restarts its services and reissues every certificate it had issued.

**4. Import into vCenter** with `certificate-manager`, option 2 ("Replace VMCA
Root certificate with Custom Signing Certificate"), giving it the full chain from
step 2 (`vmca-fullchain.pem`).

## Limits worth knowing before you start

- **vCenter does not allow sub-CAs of VMCA.** `path_len: 0` matches that.
- **Not more than one DNS name**, and no wildcards, in the VMCA certificate.
  SANs come from the profile, not the CSR, so this is controlled by the
  profile's `sans` block.
- **Key size 2048 to 8192 bits.** CryptOS enforces its own floor of 3072 on any
  subject key it certifies, so the usable range here is 3072 to 8192.
- **Name constraints are not yet supported** by the profile surface. Limiting
  what a subordinated platform CA may issue is tracked separately.

## What is covered by tests

`internal/node/vmca_subordination_test.go` drives the real `SignSubordinate`
path with a request shaped like VMCA's and asserts every published requirement
above: the whole returned chain is RSA SHA-2 signed, the certificate is v3 with
`CA:TRUE`, carries certificate and CRL signing, has no extended key usage beyond
`serverAuth`, has at most one DNS name, has a key inside vCenter's size range,
and verifies as a chain.

So "will vCenter accept what we issue" is answered by CI rather than during a
maintenance window. What CI cannot answer is whether your hierarchy is RSA — that
is a property of the CA you sign with.
