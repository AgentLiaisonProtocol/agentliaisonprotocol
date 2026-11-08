-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Notifications that wait until a grant's quiet hours end (spec 6.7), version 7. Each names the received message it
-- is about; `takeDueNotices` deletes the due ones and returns them in one statement, so of several instances sharing
-- the database each notification goes to one. Row-level security is on, as migration 004 asks of every table.
create table deferred_notices (
  id text primary key,
  principal_id text not null,
  due_at timestamptz not null,
  rec jsonb not null
);
create index deferred_notices_due on deferred_notices (due_at, id);
alter table deferred_notices enable row level security;
