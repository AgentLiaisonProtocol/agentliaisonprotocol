-- SPDX-License-Identifier: FSL-1.1-ALv2
-- The client binding's state (src/storage/postgres-binding.ts), version 2: what src/oauth/state.ts keeps in memory or
-- binding.json for a local broker. A hosted broker runs several instances at once, so all of it lives here.
-- Keys of oidc-provider artifacts are the SHA-256 of their ids (an opaque token's id is the token), and personal
-- access tokens are kept as hashes. oidc-provider also copies each id into the payload (`jti`); until migration 005 the
-- payloads of refresh tokens, authorization codes and sessions kept it, so those rows held usable tokens. From 005 on,
-- the adapter leaves it out (src/oauth/adapter.ts) and nothing in these tables is a usable token. One credential is kept
-- as issued: a dynamically registered confidential client's client_secret, in its Client payload.

-- The authorization server's models: Grant, Session, Interaction, AuthorizationCode, AccessToken, RefreshToken,
-- Client (dynamic registrations), ReplayDetection and the rest. Columns besides payload are what queries look up by.
create table oauth_artifacts (
  model text not null,
  key text not null,
  payload jsonb not null,
  expires_at timestamptz,
  grant_id text,
  uid text,
  account_id text,
  client_id text,
  primary key (model, key)
);
create index oauth_artifacts_grant on oauth_artifacts (model, grant_id) where grant_id is not null;
create index oauth_artifacts_uid on oauth_artifacts (model, uid) where uid is not null;
create index oauth_artifacts_account on oauth_artifacts (account_id, client_id) where model = 'Grant';
create index oauth_artifacts_expires on oauth_artifacts (expires_at) where expires_at is not null;

-- Personal access tokens (spec 5.7): the SHA-256 of the token, never the token.
create table pats (
  id text primary key,
  hash text not null unique,
  principal_id text not null,
  delegate text not null,
  created_at text not null,
  rec jsonb not null
);
create index pats_principal on pats (principal_id);
create index pats_delegate on pats (delegate);

-- Connection requests an agent filed, held for its person (spec 6.2.1).
create table pending_connections (
  id text primary key,
  principal_id text not null,
  created_at text not null,
  rec jsonb not null
);
create index pending_connections_principal on pending_connections (principal_id);

-- alp_send idempotency records, kept 24 hours (spec 10.3).
create table idempotency (
  key text primary key,
  at timestamptz not null,
  result jsonb not null
);
create index idempotency_at on idempotency (at);
