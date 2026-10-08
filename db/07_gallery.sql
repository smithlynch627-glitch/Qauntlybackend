-- =====================================================================================
-- Quantly: up to three extra images per collection (shown with the logo on the mint page),
-- plus size limits on the About fields, enforced by the database.
--
-- Only for a database created BEFORE this file existed. Running db/setup_all.sql again does the same
-- thing and also updates the security report, so prefer that. Safe to run more than once.
-- Until one of them has run, the website keeps working; only saving extra images is refused.
-- =====================================================================================

do $$
declare s text;
begin
  for s in select nspname from pg_namespace where nspname ~ '^chain_[0-9]+$' loop
    if to_regclass(format('%I.collections', s)) is not null then
      execute format($a$alter table %I.collections add column if not exists gallery jsonb not null default '[]'$a$, s);
      if not exists (select 1 from pg_constraint where conname = 'collections_gallery_check' and conrelid = format('%I.collections', s)::regclass) then
        execute format($a$alter table %I.collections add constraint collections_gallery_check
          check (jsonb_typeof(gallery) = 'array' and jsonb_array_length(gallery) <= 3 and pg_column_size(gallery) <= 4096
         and not jsonb_path_exists(gallery, '$[*] ? (@.type() != "string")'))$a$, s);
      end if;
      if not exists (select 1 from pg_constraint where conname = 'collections_about_check' and conrelid = format('%I.collections', s)::regclass) then
        execute format($a$alter table %I.collections add constraint collections_about_check
          check ((about is null or char_length(about) <= 8000)
             and (about_image_url is null or char_length(about_image_url) <= 500)
             and jsonb_typeof(about_items) = 'array' and jsonb_array_length(about_items) <= 12 and pg_column_size(about_items) <= 32768)$a$, s);
      end if;
    end if;
  end loop;
end $$;
