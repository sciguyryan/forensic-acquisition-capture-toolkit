# Confidential access architecture

FACT treats cryptographic possession and authenticated authority as separate requirements. A technically valid private key must never, by itself, be interpreted as current permission to decrypt confidential material.

The current v2.17 foundation introduces provenance-aware confidential access grants. It does not yet replace the existing confidential-note GnuPG representation with the planned envelope-encryption format. Selecting and implementing the eventual authenticated encryption, DEK wrapping and threshold-recovery primitives remains separate reviewed cryptographic work.

## Core invariant

> Cryptographic possession does not override authenticated access state. FACT must evaluate current authority before every protected decryption operation.

A confidential object can have several independent access grants for the same operator. Each grant records why access exists. Revoking one basis does not revoke another surviving basis.

The initial authority-basis vocabulary is:

- `object-owner`: direct authority over the confidential object itself.
- `explicit-grant`: access deliberately granted to an operator independently of a broader role.
- `project-owner`: access derived from being the current project owner.
- `case-role`: reserved for future case-derived access policy.
- `recovery-authority`: reserved for exceptional recovery operations and not ordinary owner access.
- `system-policy`: reserved for narrowly defined future system-derived authority.

The vocabulary is deliberately small. New bases should be added only when they represent materially different authority semantics that verification and audit tooling can explain.

## Multi-basis access

An operator may have more than one active basis for the same object. For example, an operator who created a confidential note while also serving as project owner can simultaneously hold `object-owner` and `project-owner` grants.

If project ownership later transfers, only the `project-owner` grant is revoked. The direct `object-owner` grant survives. This preserves the distinction between access derived from a temporary project role and access held directly over an object.

Effective confidential access is therefore true when at least one authenticated grant remains active.

## Immutable grant history

Access changes are append-only authority events. `CONFIDENTIAL_ACCESS_GRANTED` records a new basis and `CONFIDENTIAL_ACCESS_REVOKED` records the end of one specific basis. Historical grants are not deleted or rewritten.

The current access table stores both grant and revocation sequences so current state can be resolved efficiently while retaining the immutable event history that explains it.

Project ownership transfer applies explicit object-level consequences. FACT records revocation of the outgoing owner's `project-owner` grants and records corresponding grants for the incoming owner. Independent bases are left untouched.

## Current cryptographic boundary

Confidential notes still use the existing GnuPG ciphertext representation. v2.17 deliberately does not claim that the eventual envelope-encryption or retroactive revocation architecture has been implemented.

The intended later architecture is to encrypt each confidential payload with a fresh data-encryption key and represent authorised access separately from the immutable encrypted payload. The final design must minimise durable standalone decryption capability, support project recovery, and permit authenticated revocation without pretending that plaintext already disclosed to an authorised operator can be erased from their knowledge or external copies.

A future revocation operation may require creating a fresh DEK and new ciphertext representation when forward cryptographic exclusion is required. Historical ciphertext and access history must remain immutable.

## Recovery boundary

The future project recovery private key is intended to be exceptional-use material protected by a finite configurable threshold recovery scheme. Recovery trustees are not ordinary project owners or routine confidential-data recipients. If fewer than the configured threshold of valid recovery shares survive, recovery is cryptographically impossible and FACT must state that plainly.

This recovery design is not implemented in v2.17. Initialisation and recovery work must build on the authority model established here rather than bypass it.

## Security limitation

FACT can prevent a revoked operator from using FACT's normal decryption path after their authenticated authority has ended, even when an old cryptographic credential remains technically valid. FACT cannot make an operator forget plaintext, keys, screenshots, exports or other material they obtained while authorised.

The security objective is therefore strong revocation of future FACT-mediated access, including historical encrypted material where the eventual cryptographic design permits it, without making impossible claims about information already disclosed.
