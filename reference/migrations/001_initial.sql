-- SPDX-License-Identifier: FSL-1.1-ALv2
-- The reference broker's Postgres store (src/storage/postgres.ts), version 1.
-- Tables live in a schema of their own (default `broker`, set by the connection's search_path), so a Supabase
-- project's REST API, which serves only the schemas it is configured to expose, never serves them. Records are
-- stored as jsonb next to the columns the store queries by. Values in ledger payloads are a separate table, so
-- retention can delete them without touching the hash chain.

create table principals (
  principal_id text primary key,
  address text not null,
  iss text not null,
  sub text not null,
  status text not null,
  rec jsonb not null
);
create index principals_address on principals (address) where status <> 'retired';
create index principals_identity on principals (iss, sub);

create table delegates (
  id text primary key,
  principal text not null,
  rec jsonb not null
);
create index delegates_principal on delegates (principal);

create table grants (
  principal text not null,
  counterparty text not null,
  rec jsonb not null,
  primary key (principal, counterparty)
);

create table revocations (
  principal text not null,
  counterparty text not null,
  rec jsonb not null,
  primary key (principal, counterparty)
);

create table connections (
  principal text not null,
  id text not null,
  rec jsonb not null,
  primary key (principal, id)
);

create table messages (
  principal text not null,
  direction text not null check (direction in ('in', 'out')),
  envelope_id text not null,
  local_id text not null unique,
  thread text not null,
  status text not null,
  to_delegate text,
  rec jsonb not null,
  primary key (principal, direction, envelope_id)
);
create index messages_page on messages (principal, direction, local_id);
create index messages_thread on messages (principal, thread);

create table threads (
  principal text not null,
  id text not null,
  rec jsonb not null,
  primary key (principal, id)
);

create table held_outbound (
  principal text not null,
  id text not null,
  rec jsonb not null,
  primary key (principal, id)
);

create table ratification_requests (
  id text primary key,
  principal text not null,
  rec jsonb not null
);
create index ratification_requests_principal on ratification_requests (principal);

create table receipts (
  key text primary key,
  rec jsonb not null
);

create table ledger (
  principal_id text not null,
  seq integer not null check (seq >= 0),
  hash text not null unique,
  entry jsonb not null,
  primary key (principal_id, seq)
);

create table ledger_payloads (
  principal_id text not null,
  seq integer not null,
  payload jsonb not null,
  primary key (principal_id, seq)
);

create table seen (
  key text primary key,
  expires_at timestamptz not null
);
create index seen_expires on seen (expires_at);

create table rate_hits (
  key text not null,
  at timestamptz not null
);
create index rate_hits_key on rate_hits (key, at);

-- Private key material. A hosted deployment encrypts the column with a key it holds outside the database (or keeps
-- signing keys in a KMS); see SELF-HOST.md.
create table keyrings (
  name text primary key,
  ring jsonb not null
);
