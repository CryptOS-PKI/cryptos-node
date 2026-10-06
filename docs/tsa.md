# Time-stamp authority (RFC 3161)

A code signature stops verifying when the signing certificate expires, unless
the signature carries a trusted timestamp proving it was made while the
certificate was valid. An Intermediate or Issuing node can serve those
timestamps as an RFC 3161 time-stamp authority (TSA), for `signtool /tr`,
`osslsigncode -ts`, `jarsigner -tsa`, `cosign --timestamp-server-url` and
`openssl ts`.

> Scope: HTTP POST of `application/timestamp-query` to the listener's root
> path, answered with `application/timestamp-reply`. No other RFC 3161
> transport (TCP, e-mail, file) is offered, and no request extension is
> accepted.

## What a token says

| Field | Value |
|---|---|
| Message imprint | Echoed from the request. SHA-256, SHA-384 and SHA-512 are accepted; SHA-1, MD5 and anything else get `badAlg` |
| Policy | `pki.tsa.policy_oid`. A request asking for another policy gets `unacceptedPolicy` |
| Serial number | 159 random bits, unique per token |
| `genTime` | UTC, to the millisecond |
| Accuracy | `pki.tsa.accuracy_ms` (1000 by default) |
| Ordering | Not claimed |
| Nonce | Echoed when the request has one |
| Signer | The TSA certificate, named in a signing-certificate-v2 attribute (RFC 5816) by its SHA-256 hash, issuer and serial. It is carried in the token only when the request sets `certReq` |

The CA key never signs a token. The node issues a separate TSA certificate
from its CA, with key usage `digitalSignature` and one extended key usage,
`id-kp-timeStamping`, marked critical as RFC 3161 requires. Its key has the CA
key's algorithm and lives where the CA key does: in the TPM on a TPM node, in
software (on the encrypted state partition) otherwise. The TSA
certificate is listed by `cryptosctl ca list-issued` under the profile `tsa`,
so it can be revoked like any other certificate, and with
`pki.revocation_base_url` set it carries the CRL, OCSP and caIssuers pointers.

## Switching it on

The TSA is off unless the `pki.tsa` block is present, and it stays off until
you set a policy OID: there is no default, so no two deployments share a policy
by accident. A Root refuses `enabled: true`.

```yaml
pki:
  tsa:
    http_port: 0                          # 0 is 318
    policy_oid: "1.3.6.1.4.1.32473.1.1"   # your own arc; see below
    accuracy_ms: 1000                     # 0 is 1000, at most 60000
    rate_limit:
      requests_per_minute: 60             # 0 is 60
      burst: 60                           # 0 is requests_per_minute
    allowed_networks: [10.0.0.0/8, "2001:db8::/32"]   # empty answers anyone
    certificate:
      validity_days: 365                  # 0 is 365, the most
      rotation_overlap_days: 30           # 0 is 30
```

`32473` is the example enterprise number from RFC 5612; replace it. A policy
OID is yours to assign under your own IANA Private Enterprise Number: request
one at <https://pen.iana.org>, then pick an arc under
`1.3.6.1.4.1.<PEN>` for your TSA policy, for example `1.3.6.1.4.1.<PEN>.1.1`,
and record what it means in your PKI policy documents.

> [!WARNING]
> Switching the TSA on or off, or changing any `pki.tsa` field, takes effect at
> the next boot. `config apply` stores the change and reports that a reboot is
> required; until then `cryptosctl status` shows the TSA configured but not
> running (or the reverse) with a pending reboot. Plan the reboot in a
> maintenance window: every listener on the node goes down with it.

To switch it off and keep the settings, send the block with `enabled: false`.

## Access

The listener is plain HTTP, as RFC 3161 describes: the token carries its own
integrity and nothing in it is confidential. RFC 3161 has no client
authentication, so the TSA answers anyone the limits let through:

- A client outside `allowed_networks` gets HTTP 403 before its request is read.
  A bare address in the list means that one host.
- Each client has a token bucket: `burst` requests at once, refilled at
  `requests_per_minute`. A client is its IPv4 address, or its IPv6 /64. Over
  the limit it gets HTTP 429 with `Retry-After`.

Put the TSA behind your own TLS front end if your signing tools require an
`https` URL.

## The clock

A timestamp is only a claim about the time, so the TSA fails closed on its
clock. Every request is answered `timeNotAvailable` while:

- no time sync has succeeded this boot, or the latest one failed (servers
  unreachable, servers disagreeing, a step refused);
- the latest sync measured an offset larger than `accuracy_ms`;
- the node has no time source at all.

The reason is in the node log. `pki.allow_unsynced_clock` does not apply to
the TSA. See [time-sync.md](time-sync.md) for the time sources and the
`Clock:` status line.

> [!CAUTION]
> Set `network.ntp_servers` (or serve NTP in the DHCP lease) before you switch
> the TSA on. Without a time source the TSA refuses every request.

## Certificates and rotation

The TSA certificate is valid for `validity_days` (capped at the CA
certificate's own expiry). `rotation_overlap_days` before it expires, the node
issues a successor with a new key and signs new tokens with it; the old
certificate stays valid for the rest of its life. A successor is also issued
when the current certificate is revoked, or when the CA key is rotated. The
node checks every hour, so this needs no reboot.

Every TSA certificate the node has signed with stays published after it is
replaced or expires, so a token signed before a rotation still verifies. Only
the key of a replaced certificate is deleted.

```sh
cryptosctl tsa certificates          # newest first; CURRENT marks the signing one
cryptosctl tsa certificates --pem    # the certificates themselves
```

## Checking a token

On any machine with OpenSSL 3, with the node's root and intermediate
certificates in `chain.pem`, build a query:

```sh
openssl ts -query -data artifact.bin -sha256 -cert -out req.tsq
```

Send it to the TSA:

**Linux / macOS**

```sh
curl -sS -H 'Content-Type: application/timestamp-query' --data-binary @req.tsq \
  -o resp.tsr http://tsa.example.org:318/
```

**Windows (PowerShell)**

```powershell
Invoke-WebRequest -Uri http://tsa.example.org:318/ -Method Post `
  -ContentType 'application/timestamp-query' -InFile req.tsq -OutFile resp.tsr
```

Read and verify the reply:

```sh
openssl ts -reply -in resp.tsr -text
openssl ts -verify -in resp.tsr -queryfile req.tsq -CAfile chain.pem
```

The last command prints `Verification: OK`.
