-- SPDX-License-Identifier: FSL-1.1-ALv2
-- No raw token ids in stored payloads, version 5. oidc-provider copies each artifact's id into its payload (`jti`), and
-- an opaque token's id is the token itself: rows written before this version held usable refresh tokens, authorization
-- codes and session cookie values in the clear, next to their SHA-256 keys. The adapter (src/oauth/adapter.ts) now
-- stores these models' payloads without `jti` and puts it back from the id on lookup (ID_IS_SECRET in
-- src/oauth/state.ts), so only the key is kept. Grants keep theirs: a grant id grants nothing on its own.
update oauth_artifacts set payload = payload - 'jti'
  where model in ('AccessToken', 'AuthorizationCode', 'RefreshToken', 'ClientCredentials', 'DeviceCode', 'BackchannelAuthenticationRequest',
                  'InitialAccessToken', 'RegistrationAccessToken', 'PushedAuthorizationRequest', 'Session', 'Interaction')
    and payload ? 'jti';
-- An interaction's copy of its session's cookie value, which oidc-provider never reads back.
update oauth_artifacts set payload = payload #- '{session,cookie}'
  where model = 'Interaction' and jsonb_typeof(payload -> 'session') = 'object' and (payload -> 'session') ? 'cookie';
