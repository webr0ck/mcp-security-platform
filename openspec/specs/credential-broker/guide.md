# credential-broker - build guide (non-normative)

`spec.md` states what must be true. This covers the key-hierarchy choice that shapes everything
else, how to build it on Vault and on a cloud KMS, and the failure this capability produces
most often in practice.

---

## 0. The decision to make first (`CRD-004`)

There are two shapes for the key hierarchy, and they differ in what an attacker gets when they
compromise the platform process.

**Shape A - the platform reads a root secret.** The platform authenticates to a secrets store,
reads a master secret, derives per-identity keys from it, and encrypts and decrypts locally.

- Fast. No network call per credential operation.
- Compromise of the platform process discloses the master secret, and therefore **every stored
  credential**, past and future, including ones the attacker never triggered.
- The secrets store protects the master secret at rest and in transit. It does not protect the
  credentials against an attacker who is inside the platform.

**Shape B - the root never leaves the store.** The platform sends data to the store to be
wrapped and unwrapped. It never holds the root key.

- Compromise of the platform discloses only what the attacker asks the store to unwrap while
  they hold access, and each of those requests is a record in the store's audit log.
- Costs a network round trip on the credential path, and makes the store a hard dependency of
  every credentialed call - which it already is under `CRD-004`'s third scenario.

`CRD-004` does not choose for you. It requires you to **say which one you built**, in those
terms. The failure it is written against is a platform that runs Shape A and describes its
credentials as "protected by the secrets store" - true against an attacker with database access,
false against the attacker the platform's own threat model is about.

If you are building new, build Shape B. If you have Shape A, the honest documentation is not
optional and the migration is `CRD-005`'s re-encryption path.

---

## 1. HashiCorp Vault

### 1.1 Shape B: Transit

Vault's transit secrets engine is Shape B and is the reason to prefer Vault here.

- Create a transit key per platform, or per tenancy if you need blast-radius separation.
- The platform calls encrypt and decrypt. The key material never leaves Vault.
- Use the derivation feature with a per-identity context so each identity's data is encrypted
  under a distinct derived key - this gives you `CRD-003`'s per-identity property without the
  platform holding anything.
- Vault's key rotation increments a key version; existing ciphertext stays decryptable under
  the version that wrote it, and a rewrap operation moves it forward without the platform ever
  seeing plaintext. That is `CRD-005`'s second scenario satisfied by the tool rather than by
  your code, which is unusual and worth taking.

Do the context binding carefully. Vault's derivation context and your AEAD additional data
serve the same purpose here, and `CRD-003`'s third scenario is about completeness: the context
must include every field that distinguishes one stored row from another - principal, server,
operation, credential kind. Leave one out and a row can be moved along that axis.

### 1.2 Shape A: KV plus local crypto

If you must read a master secret from Vault's key-value store, then:

- Authenticate with AppRole or a workload identity method, not a static token in the deployment
  description (`CRD-004`, fourth scenario).
- Keep the secret in memory only, and be aware that "in memory only" is a weaker statement in a
  garbage-collected runtime than it sounds - you cannot reliably zero it.
- Write the `CRD-004` documentation paragraph before you ship, not after.

### 1.3 Authentication and its own failure mode

Whichever shape, the platform's authentication to Vault has a lease and will expire. Renew it,
and treat renewal failure as `CRD-004`'s third scenario - credentialed operations fail closed.
A broker that keeps serving on a cached master secret after its Vault authentication lapsed is
a broker whose fail-closed property exists only until the first token expiry.

---

## 2. Cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault)

These are Shape B by construction for the data key, and the standard pattern is envelope
encryption:

1. Ask the KMS to generate a data key. You get it in plaintext and wrapped under the KMS key.
2. Encrypt the credential locally with the plaintext data key, with your AEAD and your context
   binding.
3. Store the ciphertext and the wrapped data key together. Discard the plaintext data key.
4. To decrypt: ask the KMS to unwrap, use it once, discard it.

Points that matter for `spec.md`:

- **Encryption context.** All three providers support an additional-authenticated-data map on
  the wrap and unwrap calls. Put the same context there as in your AEAD's additional data. This
  gives you a second enforcement of `CRD-003`'s binding, at the KMS, and it appears in the KMS
  audit log so a substitution attempt is visible.
- **Per-identity keys.** A data key per stored credential satisfies `CRD-003`'s per-value salt
  and per-identity derivation naturally. Do not share one data key across principals to save
  calls - that is the property you are paying for.
- **Rotation.** KMS key rotation changes the key used for new wraps and keeps old versions for
  unwrap, so `CRD-005` is again mostly handled. Your re-encryption pass is still needed to move
  old values forward, and `CRD-005`'s third scenario means it must checkpoint and resume.
- **The bypass to watch.** The platform's cloud identity must not hold permission to disable
  the key, delete it, or alter its policy. Grant encrypt and decrypt, nothing more. Otherwise a
  compromised platform can quietly grant itself broader access, and your `CRD-004` boundary is
  narrower than you documented.

---

## 3. Cipher choice (`CRD-003`)

`spec.md` states properties, not a cipher, deliberately. Two families work:

- **AES-GCM** with a 256-bit key. Widely available, hardware-accelerated. Its constraint is that
  nonce reuse under one key is catastrophic - it discloses the authentication key. With random
  96-bit nonces, keep the number of encryptions under one key well below the birthday bound, or
  derive a fresh key per value so the count is one.
- **XChaCha20-Poly1305.** The 192-bit nonce makes random nonce generation safe at any realistic
  volume, which removes the reuse concern rather than bounding it. Not available in every
  standard library.

Either satisfies `CRD-003`. The requirement that decides your implementation is "a nonce is
never reused under a given key" - if you derive a key per stored value, both are safe; if you
share a key across many values with AES-GCM, you have a counting obligation you must actually
meet.

`CRD-003`'s fourth scenario needs a version or scheme identifier stored alongside every
ciphertext. Add it on day one. Retrofitting a scheme identifier onto values that do not have
one means guessing, and guessing wrong on a credential blob is indistinguishable from
tampering.

---

## 4. The failure this capability actually produces

Not a crypto break. **Provisioning tooling that writes credentials a different way from the
request path.**

A seeder, a migration, or an operational script constructs the stored value with a slightly
different context - a field omitted from the additional data, a different key derivation input,
an older master secret. Everything looks fine until injection time, when every affected
credential fails authentication and the platform reports "credential not provisioned". The
error names the wrong cause and the investigation goes to the broker instead of the seeder.

`CRD-006`'s second scenario is written for this. Enforce it structurally: one codec function,
and the tooling imports it. If a script cannot import it, that script must not write
credentials.

Symptom to recognise: credentials that were working stop working after an unrelated deployment
or a re-seed, and the failure is uniform across principals rather than scattered.

---

## 5. Token exchange in practice (`CRD-008`)

Read `identity-authentication/guide.md` §0 first - whether you get this path at all is an IdP
property, and the answer is "no" more often than the design assumes.

When you do have it:

- Request a scope no wider than the subject token's. Some servers will happily issue wider on
  request, and a broker that asks for everything has re-created the over-broad token the
  platform exists to eliminate.
- **Verify the returned audience** rather than trusting it (`CRD-008`, third scenario). The
  exchange asked for a restriction; the server may not have applied it, and an unverified
  assumption here means one backend can replay at another.
- Cache exchanged tokens keyed on principal *and* backend, and invalidate on session revocation
  (`CRD-002`, third scenario). A cache keyed only on backend hands one principal's token to
  another - the single worst bug available in this capability.
- Failure of the exchange fails the call. Never fall back to a stored credential belonging to
  someone else (`CRD-008`, last scenario).

---

## 6. Checklist

- [ ] Key-hierarchy shape chosen and its compromise boundary documented in those terms - `CRD-004`
- [ ] Root material never sourced from an environment variable or the deployment artifact - `CRD-004`
- [ ] Root or wrapping service unreachable fails credentialed operations closed - `CRD-004`
- [ ] Platform identity holds encrypt and decrypt only, not key administration - `CRD-004`
- [ ] Per-identity key derivation with a fresh salt per stored value - `CRD-003`
- [ ] Additional authenticated data includes every field distinguishing one stored context - `CRD-003`
- [ ] Nonce uniqueness guaranteed by construction, not by assumption - `CRD-003`
- [ ] Scheme or version identifier stored with every ciphertext from day one - `CRD-003`
- [ ] Rotation keeps old values decryptable; re-encryption pass checkpoints and resumes - `CRD-005`
- [ ] Post-compromise rotation of the root not presented as remediation for the credentials - `CRD-005`
- [ ] One codec; seeding, migration and operational tooling all import it - `CRD-006`
- [ ] No read path returns plaintext credential material to any caller, including administrators - `CRD-001`
- [ ] Diagnostic and replay surfaces mask credentials - `CRD-001`
- [ ] Backend-echoed credentials redacted before agent response and before audit - `CRD-001`
- [ ] Plaintext cleared on exception paths - `CRD-002`
- [ ] Exchanged-token cache keyed on principal and backend; invalidated on session revocation - `CRD-002`
- [ ] Injection overwrites rather than merges caller-supplied fields - `CRD-007`
- [ ] Unknown and empty injection modes deny, never degrade to no-credential - `CRD-007`
- [ ] Mode-versus-source mismatch rejected at registration, not at first invocation - `CRD-007`
- [ ] Exchange requests a scope no wider than the subject token's - `CRD-008`
- [ ] Returned audience verified, not assumed - `CRD-008`
- [ ] Exchange failure never falls back to another principal's credential - `CRD-008`, `CRD-010`
- [ ] Multiple candidates at one precedence level fail closed - `CRD-010`
- [ ] Enrolment audited without recording the value - `CRD-009`
- [ ] Shared service credential upload requires dual control - `CRD-009`
- [ ] Every stored credential carries owner, context, expiry or review date - `CRD-011`
- [ ] Credentials revoked when the owning principal is retired - `CRD-011`
- [ ] Past-review credentials enumerable and alertable - `CRD-011`
- [ ] Broker actions carry the operation's correlation identifier - `CRD-012`
