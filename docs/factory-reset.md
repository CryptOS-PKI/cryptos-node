# Factory reset: quorum plus holder TOTP

> **Status: design, not built.** Nothing here is implemented yet. The
> requirement is fixed; the choices under [Open questions](#open-questions) are
> **not decided**. Tracked in #361.

## Purpose

A factory reset destroys a node's CA for good: the state-partition key material
is erased, the node reboots into maintenance and must be set up again. Today one
person can start it. The console, `cryptosctl reset` on the local socket and the
admin-authorized `RemoteReset` RPC each need only the Root CA common name typed
back (`RemoteReset` also needs the admin client certificate).

On a node that runs an M-of-N quorum, a factory reset must need:

1. the existing M-of-N quorum approval, **and**
2. three TOTP codes, from three **different** quorum holders.

Each holder's TOTP secret comes from a per-node secret that the node generates
once, at first boot, inside itself: RSA-4096 key material that is sealed, never
exported and never shown to anyone. A factory reset destroys that secret along
with the rest of the node's state, so the next first boot generates a new one
and every holder enrols again.

## Where this sits today

- `internal/reset` (`Wipe`, `CheckConfirm`) is the one destructive path. It
  checks the CN in constant time, erases the state device, clears the staged ESP
  config best-effort and reboots. On an erase failure it returns without
  rebooting, so the node keeps serving.
- `internal/storage/luks` `Erase` runs `cryptsetup luksErase` and then zeroes
  the first 16 MiB of the device, because `luksErase` leaves the LUKS header in
  place (#218). With no header copy left, the next boot takes the first-boot
  format path.
- The state-partition key is sealed to the TPM under a PCR policy (PCR 7 and
  11, `internal/tpm` `SealToPCR`), and the CA signing key is created in the TPM
  under the SRK; neither private part leaves the TPM in the clear.
- The ceremony is 1-of-1. The `CeremonyManifest` schema is shaped for M-of-N
  (`operator_signatures` is repeated), but no quorum is built yet.

The new gate goes in front of `reset.Wipe`, so all three entry points share it
the same way they share `CheckConfirm` today.

## Flow

With a quorum configured:

1. An operator starts a reset (console `^R`, `cryptosctl reset`, or
   `RemoteReset`) and types back the Root CA CN, as today. A mismatch refuses
   with nothing erased.
2. The node requires an M-of-N quorum approval for this reset request, using the
   quorum mechanism and its signed approvals. The approval names this node and
   this reset request so it cannot be replayed.
3. The node asks for three TOTP codes, each tagged with the holder it belongs
   to. Each code is checked against that holder's derived secret.
4. Only when the CN, the quorum approval and three codes from three distinct
   holders all verify does the node call `reset.Wipe`. The approval, the holder
   IDs (never the codes) and the outcome are written to the audit log before the
   erase.
5. The erase destroys the state partition, and with it the TOTP root. The node
   reboots into maintenance.

Nothing is erased until every check passes. Any failure leaves the node serving
with its identity and its TOTP root intact.

## Secret lifecycle

| Stage | What happens |
| --- | --- |
| First boot | The node generates the TOTP root inside itself (RSA-4096 key material, TPM-resident or TPM-sealed like the existing keys). No API, console screen or log ever returns it. |
| Storage | The root, or its sealed blob, lives only on the encrypted state partition and in the TPM, so it is bound to this node and this boot chain. |
| Per-holder secret | Each holder's TOTP secret is derived from the root and the holder's ID (how is open question 2). A holder only ever sees their own derived secret. The root itself is never known to anyone. |
| Enrolment | At quorum setup, each holder enrols an authenticator from their derived secret, shown once (for example as an `otpauth://` QR code) and confirmed by entering a valid code before it counts. |
| Use | Codes are RFC 6238 TOTP (time step and digits to be fixed in the build). The node keeps the last accepted time step per holder to refuse reuse. |
| Factory reset | The erase destroys the root with the state partition. Any TPM object or sealed blob for it goes too. Old codes can never verify again. |
| Next first boot | A new root is generated; every holder enrols again at the new quorum setup. |

## Console screens

The reset screens in `internal/console/confirm.go` and their golden files under
`internal/console/testdata/screens/` change:

- **reset-confirm** (and `compact-reset-confirm`, `reset-confirm-64x24`): after
  the CN, the screen shows the quorum approval state and then one entry line per
  TOTP code, each with its holder, plus a count of codes accepted (for example
  `2 of 3`).
- **reset-mismatch** (and compact, 64x24): today it covers only a CN mismatch.
  It also covers a missing or invalid quorum approval and a refused code, still
  ending in "Nothing was erased." and the return to status. A refused code says
  why in plain words (wrong or expired code, code already used, holder already
  counted) without saying which part of a code was wrong.
- **resetting** (and compact, 64x24): unchanged in meaning; it appears only once
  every check has passed.

The 64x24 and compact layouts must fit the extra lines; the CN may still wrap.
Codes are masked on screen once entered.

## Failure handling

- **Wrong code:** refused, nothing erased, audited with the holder ID. Repeated
  failures are rate limited per holder and per reset request.
- **Code reused within its window:** refused. A code for a time step at or
  before that holder's last accepted step never verifies again.
- **Same holder twice:** the second code from a holder already counted is
  refused; three codes always mean three distinct holders.
- **Clock skew:** accept the current step plus a small window either side (for
  example one step). Reset already depends on the clock the way signing does
  (see `docs/time-sync.md`); whether reset refuses on an unsynced clock is open
  question 5.
- **Approval expired or for another request:** refused; the operator starts
  again.
- **Erase fails after all checks pass:** as today, `Wipe` returns without
  rebooting and the node keeps serving. The accepted codes are spent; a retry
  needs fresh codes.

## Open questions

**None of these is decided.** Each lists the options and a recommended default
for the owner to accept or change.

1. **How many TOTP codes.**
   - (a) exactly 3, always;
   - (b) equal to M;
   - (c) max(3, M). *Recommended default:* (a), as the requirement states;
     revisit if M grows past 3.
2. **What the TOTP secrets derive from.**
   - (a) from RSA-4096 key material, for example a per-holder HKDF over a
     deterministic signature (RSASSA-PKCS1-v1_5, since PSS is randomized) of a
     fixed label plus the holder ID;
   - (b) from a sealed random seed (32 bytes) per node, with a per-holder HKDF.
   - TOTP is HMAC-based and needs a symmetric secret, and the holder's
     authenticator has to hold its derived secret either way. An RSA key gives
     no more strength there than a 256-bit random seed, needs deterministic
     signing and a TPM signing call per verification, and ties the scheme to RSA
     padding details. A random seed is simpler; the RSA-4096 option keeps the
     literal requirement and reuses the existing TPM key code.
     *Recommended default:* (a), as stated, unless the owner accepts (b).
3. **Enrolment when holders change.**
   - (a) a holder joining or leaving, or replacing a lost device, needs a
     quorum approval; the new holder (or device) enrols from a fresh per-holder
     secret (a per-holder counter in the derivation) and the old one stops
     verifying;
   - (b) changes only at quorum setup; any change means a new quorum setup.
     *Recommended default:* (a).
4. **Fewer than three holders (N < 3).**
   - (a) refuse to configure a quorum with N < 3, so a reset can always collect
     three codes;
   - (b) require codes from every holder when N < 3;
   - (c) allow one holder to supply more than one code. *Recommended default:*
     (a); (c) defeats the distinct-holder rule.
5. **Reset with an unsynced clock.**
   - (a) refuse until the clock syncs;
   - (b) accept with a wider window. *Recommended default:* (a), matching the
     signing gate.
6. **Before the quorum exists.** The ceremony is 1-of-1 today.
   - (a) the TOTP gate ships with the quorum and nodes without one keep the
     current CN-only reset;
   - (b) ship the TOTP root and enrolment for the single operator now, needing
     one code until the quorum lands. *Recommended default:* (a).
