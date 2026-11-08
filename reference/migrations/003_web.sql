-- SPDX-License-Identifier: FSL-1.1-ALv2
-- The person's web view (src/web), version 3: sessions, WebAuthn challenges, invites, passkeys and known devices, so a
-- hosted broker can serve the view from any instance. Sessions are keyed by the SHA-256 of the cookie's value, and an
-- invite keeps only a scrypt hash of its sign-in secret.

create table web_sessions (
  id_hash text primary key,
  principal_id text not null,
  rec jsonb not null,
  expires_at timestamptz not null
);
create index web_sessions_principal on web_sessions (principal_id);
create index web_sessions_expires on web_sessions (expires_at);

-- Single-use WebAuthn challenges, each bound to one session and to the hash of what the person approves.
create table web_challenges (
  challenge text primary key,
  session_hash text not null,
  rec jsonb not null,
  expires_at timestamptz not null
);
create index web_challenges_session on web_challenges (session_hash);

create table invites (
  id text primary key,
  username text not null,
  created_at text not null,
  rec jsonb not null
);
create index invites_username on invites (username);

create table passkeys (
  credential_id text primary key,
  principal_id text not null,
  counter bigint not null,
  rec jsonb not null
);
create index passkeys_principal on passkeys (principal_id);

-- Browsers a person has signed in from (the SHA-256 of a device cookie), for the notice on a new device.
create table web_devices (
  principal_id text not null,
  device_hash text not null,
  first_seen timestamptz not null,
  last_seen timestamptz not null,
  primary key (principal_id, device_hash)
);
