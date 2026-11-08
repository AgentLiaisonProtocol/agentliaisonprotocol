# Operator statement template: a hosted ALP broker

**Template.** The Agent Liaison Protocol (ALP) requires a hosted broker to publish an operator statement, kept current and dated (spec Section 13.9). This is a starting point for an operator of an invite-only broker run for evaluation with the reference broker, within its license ([LICENSE.md](../LICENSE.md), FSL-1.1-ALv2). Each `[[DECIDE: ...]]` marks a decision only the operator can make; find them with `grep -n '\[\[DECIDE' reference/deploy/OPERATOR-STATEMENT.md`. Publish the statement only when none is left, and link it from the domain document's `operator_statement` member if the broker ever federates.

What the statement says about the software describes the reference broker in this repository as configured in `reference/deploy/VERCEL-SUPABASE.md`. If the deployment differs, change the statement to match.

---

**Operator:** [[DECIDE: the operator's legal entity name and registered address]]
**Service:** [[DECIDE: the service's name]], at [[DECIDE: the broker's origin, for example https://alp.example.com]]
**Statement date:** [[DECIDE: date of publication]]. Earlier versions: [[DECIDE: where past versions are kept, for example a dated list on this page]].

## What the service is

An invite-only broker for the Agent Liaison Protocol (ALP) v0.1 draft, run by the operator for evaluation. It is home to addresses on [[DECIDE: the service's own domain]] only; it is not home to addresses on any customer's or employer's domain. It is for evaluation with test data, not for confidential, regulated or production data. People join only by invitation, and can be removed at any time.

ALP secures one channel: typed messages between people's home brokers, under each person's rules. The broker can't control what an agent product does with what it reads, or how that product's vendor stores it. Those are governed by each vendor's own terms.

## 1. How people are verified (spec Section 5.3)

- **Invitation.** The operator invites each person individually. An invitation names the person's sign-in name and ALP address, carries a sign-in secret for that person alone (192 random bits, delivered by the operator over [[DECIDE: the channel used to deliver invitation secrets]]; the broker stores only a scrypt hash of it), and expires after at most [[DECIDE: invitation lifetime, at most 90 days]].
- **Passkey.** The secret only starts a person's first sign-in. Before anything else works, the person registers a passkey (WebAuthn, with user verification). Every later sign-in, every approval on the person's page (connections, commitments, grants, disconnections, personal access tokens), and every connection of a new agent needs a fresh passkey check. The check's challenge carries a hash of exactly what the person is approving.
- **Assurance.** An invitation establishes that the operator chose to admit whoever received the secret; the service does not verify legal identity. [[DECIDE: whether the operator checks anything more before inviting, for example a work email]]. Sign-in through an organization's identity provider (for example Microsoft Entra ID) is not available on a broker that signs people in by invite.
- **Recovery.** A person who loses their passkey can't recover access by email. The operator re-admits them by [[DECIDE: the recovery procedure, for example a new invitation after a video call]].
- **Removal.** Revoking an invitation stops new sign-ins and ends the person's open sessions at once. Agents the person already connected keep their access until the person disconnects them on their page or the operator blocks the person (within 60 seconds of the change).

## 2. Training, advertising and retention

- The operator does not use message content or metadata to train models or for advertising, and does not let its subprocessors do so.
- **Message payloads** (the field values people's agents exchange) are kept for [[DECIDE: maximum retention of payloads, for example 30 days]], then deleted. The reference broker's per-person ledger keeps each entry's hash chain without its payload, so deleting a payload doesn't break the chain.
- **Metadata** (who exchanged what kind of message with whom, when, and the decisions; sign-in records; security events) is kept for [[DECIDE: maximum retention of metadata, for example 12 months]].
- **Operational logs** at the hosting providers are kept for [[DECIDE: log retention at the hosting and database providers]].
- When the service ends, the operator deletes its data within [[DECIDE: deletion period after the service ends]], after giving people [[DECIDE: notice period]] to export it (Section 7).

Today's limits, stated plainly: the reference broker doesn't yet delete payloads on a timer (an operator task until it is built), and it refuses messages that ask for a retention limit it can't keep.

## 3. Where data is processed, and legal process

- **Jurisdiction:** [[DECIDE: governing law and the operator's jurisdiction]].
- **Processing locations:** the broker runs on Vercel in [[DECIDE: Vercel function region]]; its database is a dedicated Supabase project in [[DECIDE: Supabase region]], used for nothing else.
- **Legal process:** the operator discloses data only in response to [[DECIDE: the legal process the operator requires, for example a valid court order in the stated jurisdiction]], tells affected people before disclosing unless legally prohibited, and [[DECIDE: whether the operator publishes a transparency report, and how often]].

## 4. Subprocessors and attestations

| Subprocessor | What it does | Data it handles | Location |
|---|---|---|---|
| Vercel | Runs the broker (functions, TLS, logs) | Requests in transit; operational logs | [[DECIDE: region]] |
| Supabase | The broker's Postgres database | Everything the broker stores (Section 2) | [[DECIDE: region]] |
| [[DECIDE: email provider, if notices are emailed]] | Sends notices (new sign-in, connection requests) | Recipient address and broker-written notice text, never message content | [[DECIDE: location]] |
| [[DECIDE: any other subprocessor, for example a log drain or monitoring service]] | | | |

The operator will announce a new subprocessor [[DECIDE: notice period before adding a subprocessor]] in advance on this page.

**Attestations:** [[DECIDE: the operator's own security attestations, or "none for an evaluation service"]]. The hosting providers' own attestations are published by them; they don't cover how the operator runs the broker.

## 5. Key custody and compromise (spec Section 4.8)

- The broker's signing keys for protocol objects (envelopes, receipts, ratification records) are stored in the database sealed with AES-256-GCM under a key-encryption key that is kept outside the database, in the hosting provider's encrypted environment settings. A copy of the database alone holds no usable signing key.
- The authorization server's token-signing and cookie keys are kept only in those environment settings, never in the database or the repository.
- Access to those settings is limited to [[DECIDE: who at the operator can read or change production secrets]], with [[DECIDE: two-factor authentication requirement and access review]].
- **If a key is compromised,** the operator rotates it, revokes affected connections and tokens, and tells affected people within [[DECIDE: notification deadline after confirming a compromise]]. While the broker doesn't federate, no other broker relies on its signing keys; if it federates later, the domain document's `revoked_jkt` carries the compromise time (spec Section 4.8).

## 6. Abuse and security contacts

- **Abuse:** [[DECIDE: abuse contact, for example abuse@example.com]]
- **Security reports:** [[DECIDE: the operator's security contact]]
- **Privacy requests:** [[DECIDE: privacy contact]]

## 7. Export

Each person can export their own ledger as JSON from their page at any time (what crossed, with whom, under which scope, and the decisions). Grants and connected agents are listed on the same page. A full export of everything the broker holds about a person, in a portable format, is available on request to [[DECIDE: the privacy contact]] within [[DECIDE: response time]]; the signed export format of spec Section 11.7 is not built yet.

## Changes to this statement

The operator will post changes here with a new date [[DECIDE: notice period before a change that reduces protections]] before they take effect, and tell invited people by [[DECIDE: how people are told]].
