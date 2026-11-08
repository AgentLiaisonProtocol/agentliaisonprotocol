-- SPDX-License-Identifier: FSL-1.1-ALv2
-- One live principal per address and per identity, version 6. The broker looks for both before it writes a principal,
-- but two first sign-ins at the same moment on two instances could each create one; with these indexes the second
-- write fails instead, and that person signs in again. Retired principals keep their address and identity for the
-- record, so the indexes leave them out.
drop index if exists principals_address;
create unique index principals_address_live on principals (address) where status <> 'retired';
create unique index principals_identity_live on principals (iss, sub) where status <> 'retired';
