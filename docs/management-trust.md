# Trusting a node's management certificate

Every remote `cryptosctl` call is mutual TLS. The client proves itself with
`--identity` and `--identity-key`, and it checks the node's certificate against
`--trust` (default `~/.cryptos/trust.crt`). This page covers `--trust`: what
it has to contain, how to get it, and when it goes stale.

## What the node presents

What the management listener (port 443) presents depends on whether the node
has its CA yet.

**Before the node has a CA** (a Root before its ceremony, a subordinate before
its certificate is accepted), the node generates a new key and a new
**self-signed** certificate at every boot. That certificate:

- is issued by itself, so it chains to nothing. Your root does not verify it,
  and neither does any other bundle.
- names two subjects: the IP address from the node's `network.address`, and
  `localhost`. It carries no DNS names.
- is replaced on the next boot. The key, serial and fingerprint all change.

So before the ceremony `--trust` has to be **the node's current management
certificate itself**, pinned, as the rest of this page describes.

**Once the node has a CA**, the listener switches to a certificate **signed by
the node's own CA**. The switch happens on the boot that commits the CA, without
a restart, from the next connection on (the console follows within about 30
seconds). That certificate:

- chains to the node's CA. The listener sends the node's CA chain with it, up to
  the root, so your root certificate verifies it at any hierarchy depth.
- names the IP address from `network.address` and every entry in
  `pki.est.hostnames`. It does not name `localhost`.
- is an end-entity server certificate (`serverAuth` only, not a CA), valid for
  90 days (never past the CA's own expiry) and renewed at the halfway point.
- gets a new key at every boot, so its fingerprint still changes. What stays the
  same is the chain.

From then on, point `--trust` at your root certificate (or the node's CA
certificate) instead of a pin. It keeps working across reboots, upgrades and
`image activate`:

```sh
cryptosctl --endpoint 192.0.2.10:443 --trust root.pem status
```

> [!WARNING]
> The pin you ran the Root ceremony over (or submitted a subordinate's
> certificate over) stops working as soon as the CA commits, so the next call
> with it fails with `x509: certificate signed by unknown authority`. A
> subordinate chains to the root you already hold. On a new Root, fetch the
> CA-signed certificate once, checked against the console, and read the root
> over it. Then compare the root's SHA-256 with the `cert_sha256` the ceremony
> printed before you rely on it:
>
> ```sh
> cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem \
>   trust fetch --expect-sha256 "<Mgmt SHA-256 from the node console>"
> cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem identity show -o pem > root.pem
> openssl x509 -in root.pem -noout -fingerprint -sha256
> ```

The node console marks the switch: under **Mgmt SHA-256** the **Mgmt cert**
line changes from **self-signed, compare the fingerprint** to **CA-signed,
trust the CA**.

> [!CAUTION]
> Do not pin a CA-signed management certificate. `trust fetch` still saves one,
> but the pin stops matching at the next boot, like a self-signed one. Trust
> the CA instead.

> [!TIP]
> This output means `--trust` does not verify the certificate the node
> presents:
>
> ```text
> x509: certificate signed by unknown authority
> ```
>
> Before the ceremony, fetch the current certificate, as in
> [Getting the current certificate](#getting-the-current-certificate), then
> retry. Once the console shows **CA-signed**, use your root certificate.

A self-signed pin taken before a reboot fails the same way afterwards. Any
reboot does it: a planned restart, `image activate`, a power event, a
hypervisor migration that restarts the guest.

A node in maintenance mode (booted from the ISO with no state disk yet, or back
after a reset with no config) always presents a throwaway self-signed
certificate for `localhost`, with a new key every boot, and asks for no client
certificate; reach it with `--insecure`. It has no configured address, only the
one DHCP gave it, so its console shows that address under **Address** and the
certificate's **Mgmt SHA-256**.

> [!CAUTION]
> Compare the console's **Mgmt SHA-256** with the fingerprint the Fleet
> Manager's adoption preview (or `openssl s_client`) shows before you adopt the
> node or apply a config to it. A different value means something else is
> answering on that address; stop and find out what before you send it a
> config.

## Getting the current certificate

Run this after the node has finished booting, and again after every reboot.
Substitute the node's management IP address.

First read the fingerprint off the node itself. The console shows a **Mgmt
SHA-256** line: the SHA-256 of the management certificate this boot, in groups
of four hex digits. It changes on every boot, like the certificate. The line is
there in maintenance mode and from the first boot from disk. Until the node has
its CA, the console shows its state, the next step, and the fingerprint, in the
same form as on the serving dashboard:

| Node | Console title | Hint |
| --- | --- | --- |
| Node in maintenance (booted from the ISO, or after a reset) | **Awaiting configuration** | Run: cryptosctl config apply |
| Root waiting for its ceremony | **Awaiting ceremony** | Fetch trust, then start the ceremony |
| Root whose ceremony has started | **Ceremony in progress** | Wait, or start it again if it failed |
| Intermediate or issuing CA waiting for its parent | **Awaiting parent certificate** | Fetch trust, then get the CSR signed |

Only the maintenance screen also shows an **Address** line: the node's IPv4
addresses, one per line. An installed node uses the address in its config.

The two screens an adoption compares against say which check they are: under
the fingerprint, the maintenance screen shows **check 1/2: compare with the
web console** and the installed Root's **Awaiting ceremony** screen shows
**check 2/2**. On a console too small for the frame, the compact screen labels
the fingerprint **SHA** and the address **IP**.

After a Fleet Manager adoption the node installs and reboots, so the
fingerprint to confirm for the installed node is the one on its console after
that reboot (**Awaiting ceremony**, or the serving dashboard once it has a CA),
not the maintenance value.

A ceremony that fails part way leaves the node on **Ceremony in progress**;
run `ceremony start` again. A subordinate stays on **Awaiting parent
certificate** until `ca submit-subordinate-cert` commits the chain its parent
signed.

> [!CAUTION]
> Verify the fingerprint before the first ceremony. `ceremony start` talks to
> whatever the pin you fetch here names, and the Root certificate it hands back
> is the one you go on to publish. With an unchecked pin, that certificate may
> come from an impostor rather than your node. Pass the console's value to
> `--expect-sha256` for that first fetch too.

> [!NOTE]
> `cryptosctl` runs on Linux and macOS today. A Windows build is coming.

Then fetch the certificate and check it against that value in one step:

```sh
cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem \
  trust fetch --expect-sha256 "2D71 1642 B726 B044 0162 7CA9 FBAC 32F5 C853 0FB1 903C C4DB 0225 8717 921A 4881"
```

`trust fetch` connects to `--endpoint`, reads the certificate the node
presents, and saves it to the `--trust` path (`~/.cryptos/trust.crt` when you
leave `--trust` out, which makes it the default for later calls). It prints the
certificate's subject, issuer, subject alternative names, expiry and SHA-256.
No client certificate is needed: the node sends its certificate before it asks
for yours.

`--expect-sha256` takes the value from the console. Spaces, colons and case are
ignored, so the `AB:CD:...` form openssl prints works too. When the node
presents a certificate with any other fingerprint, `trust fetch` fails and saves
nothing. Without `--expect-sha256` it saves whatever it received and says the
pin is not verified; compare the printed SHA-256 with the console before you
rely on it.

> [!TIP]
> Check that the subject alternative names are the node's IP and `localhost`,
> and that the certificate is self-signed (subject and issuer match). Then pass
> `--trust node-trust.pem` on each call, or fetch straight into the default path.

Without `cryptosctl` at hand, openssl gets the same certificate and
fingerprint:

**Linux / macOS**

```bash
openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > node-trust.pem
openssl x509 -in node-trust.pem -noout -subject -issuer -enddate -fingerprint -sha256 -ext subjectAltName
```

**Windows (PowerShell)**

```powershell
'Q' | openssl s_client -connect 192.0.2.10:443 -servername 192.0.2.10 2>$null |
  openssl x509 -outform PEM -out node-trust.pem
openssl x509 -in node-trust.pem -noout -subject -issuer -enddate -fingerprint -sha256 -ext subjectAltName
```

## Address the node by IP

The self-signed certificate has no DNS names. Hostname verification only passes
when the name `cryptosctl` checks is the node's IP. Use the IP in `--endpoint`:

```sh
cryptosctl --endpoint 192.0.2.10:443 --trust node-trust.pem status
```

If you have to connect through a DNS name, add `--server-name 192.0.2.10` so
verification checks the IP the certificate names. `localhost` only works on the
node itself, and only before the ceremony.

The CA-signed certificate also names each `pki.est.hostnames` entry, so once the
node has its CA you can connect through any of those names without
`--server-name`.

## What this pin does and does not prove

A fetch checked against the console's **Mgmt SHA-256** is a verified pin: the
certificate you saved is the one the node generated this boot, so later calls
reach your node. Reading the console needs access to it (the physical screen or
the hypervisor console), which is the out-of-band channel the check relies on.

> [!CAUTION]
> A fetch you did not check is trust on first use. The pin tells you that later
> calls reach the same endpoint that answered the fetch. It does not tell you
> that endpoint is your node.

For an unchecked pin, what limits the damage is the mutual TLS. An impostor
that answered the fetch still does not hold your admin key, so it cannot relay
your calls to the real node. At worst it pretends to be the node. For each operation, decide what a
fake answer would cost:

- **Signing** (`ca sign-subordinate`). A fake node cannot make a
  certificate that chains to your root. Verify the result against your root
  offline before you use it (see
  [`vmca-subordination.md`](vmca-subordination.md), step 3). A certificate
  that verifies came from your CA, however the pin was obtained.
- **Anything you send to the node.** This covers `config apply`,
  `ca import-key`, and any other request that carries material you would not
  publish. That material goes to whoever answered the fetch. Take the fetch
  from a host on the node's management network, over a path you control, not
  across a segment you do not trust.
- **Anything the node sends back.** For example, a status or identity response.
  Treat it as unauthenticated unless you can check it independently.

When you are finished, delete `node-trust.pem`, or leave it knowing it stops
matching after the next boot. Once the node has its CA, switch to trusting the
CA. A stale pin fails closed. It never makes a
connection succeed that should not.
