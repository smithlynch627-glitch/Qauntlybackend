-- Profile privacy for existing databases (already part of 01_schema.sql and setup_all.sql).
-- Run once in Supabase → SQL Editor. Safe to run again.
--
-- A wallet can hide its collected items and its activity on Quantly's pages and in the public API.
-- The wallet itself still sees everything when signed in. On-chain data stays public on the explorer.

alter table app.users add column if not exists hide_collected boolean not null default false;
alter table app.users add column if not exists hide_activity boolean not null default false;
