-- Aşama 1: şema + RLS + storage politikaları
create extension if not exists pgcrypto;
create type public.app_role as enum ('admin','teacher','user');
create type public.doc_scope as enum ('shared','personal');

create table public.roles(role app_role primary key, description text not null);
insert into public.roles values ('admin','Yönetici'),('teacher','Öğretmen'),('user','Standart Kullanıcı');

create table public.profiles(
  id uuid primary key references auth.users on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9._-]{3,32}$'),
  full_name text not null default '',
  role app_role not null default 'user' references public.roles(role),
  is_active boolean not null default true,
  created_at timestamptz not null default now());

create function public.role_rank(r app_role) returns int language sql immutable as
$$ select case r when 'admin' then 3 when 'teacher' then 2 else 1 end $$;
create function public.is_admin() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and role='admin' and is_active) $$;
create function public.is_active_user() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and is_active) $$;
create function public.my_role() returns app_role language sql stable security definer set search_path=public as
$$ select role from profiles where id=auth.uid() and is_active $$;

create table public.categories(
  id uuid primary key default gen_random_uuid(),
  name text not null unique, slug text not null unique,
  min_read_role app_role not null default 'user',
  min_upload_role app_role not null default 'teacher',
  sort int not null default 0);
create table public.folders(
  id uuid primary key default gen_random_uuid(),
  parent_id uuid references public.folders on delete cascade,
  category_id uuid references public.categories,
  scope doc_scope not null default 'shared',
  owner_id uuid not null references public.profiles default auth.uid(),
  name text not null check (length(name) between 1 and 120),
  created_at timestamptz not null default now());
create table public.documents(
  id uuid primary key default gen_random_uuid(),
  scope doc_scope not null,
  owner_id uuid not null references public.profiles default auth.uid(),
  category_id uuid references public.categories,
  folder_id uuid references public.folders on delete set null,
  title text not null check (length(title) between 1 and 200),
  description text, tags text[] not null default '{}',
  course text, school_year text, doc_type text,
  mime text not null, size_bytes bigint not null check (size_bytes <= 26214400),
  storage_path text not null unique,
  enc_iv text not null, enc_wrapped_key text not null,
  current_version int not null default 1,
  deleted_at timestamptz,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
  check (scope='personal' or category_id is not null),
  fts tsvector generated always as (to_tsvector('simple',
    coalesce(title,'')||' '||coalesce(description,'')||' '||coalesce(course,'')||' '||coalesce(school_year,'')||' '||coalesce(doc_type,''))) stored);
create index on public.documents using gin(fts);
create index on public.documents(category_id, created_at desc);
create index on public.documents(owner_id, scope);
create table public.document_versions(
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.documents on delete cascade,
  version int not null, storage_path text not null unique,
  enc_iv text not null, enc_wrapped_key text not null, size_bytes bigint not null,
  created_by uuid not null default auth.uid(), created_at timestamptz not null default now(),
  unique(document_id, version));
create table public.document_permissions(
  document_id uuid references public.documents on delete cascade,
  user_id uuid references public.profiles on delete cascade,
  can_write boolean not null default false,
  primary key(document_id,user_id));
create table public.shared_files(
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references public.documents on delete cascade,
  shared_with uuid references public.profiles on delete cascade, -- null = tüm aktif kullanıcılar
  shared_by uuid not null default auth.uid(), created_at timestamptz not null default now());
create table public.favorites(
  user_id uuid not null default auth.uid() references public.profiles on delete cascade,
  document_id uuid references public.documents on delete cascade,
  primary key(user_id,document_id));
create table public.announcements(
  id uuid primary key default gen_random_uuid(),
  title text not null, body text not null,
  author_id uuid not null default auth.uid(), created_at timestamptz not null default now());
create table public.activity_logs(
  id bigint generated always as identity primary key,
  user_id uuid default auth.uid(), action text not null,
  target_type text, target_id text, meta jsonb, created_at timestamptz not null default now());
create table public.user_settings(
  user_id uuid primary key default auth.uid() references public.profiles on delete cascade,
  theme text not null default 'system' check (theme in ('light','dark','system')));
-- İstemci taraflı şifreleme: yalnızca SARILMIŞ anahtarlar saklanır
create table public.user_keys(
  user_id uuid primary key default auth.uid() references public.profiles on delete cascade,
  kdf_salt text not null, kdf_iters int not null default 600000,
  wrapped_private_key text not null, public_key text not null,
  wrapped_dept_key text,
  created_at timestamptz not null default now());

create function public.can_read_doc(d public.documents) returns boolean language sql stable security definer set search_path=public as $$
  select public.is_active_user() and d.deleted_at is null and (
    public.is_admin() or d.owner_id=auth.uid()
    or exists(select 1 from document_permissions p where p.document_id=d.id and p.user_id=auth.uid())
    or exists(select 1 from shared_files s where s.document_id=d.id and (s.shared_with is null or s.shared_with=auth.uid()))
    or (d.scope='shared' and exists(select 1 from categories c where c.id=d.category_id
         and public.role_rank(public.my_role()) >= public.role_rank(c.min_read_role))))
$$;

do $$ declare t text; begin
  foreach t in array array['profiles','roles','categories','folders','documents','document_versions','document_permissions',
    'shared_files','favorites','announcements','activity_logs','user_settings','user_keys']
  loop execute format('alter table public.%I enable row level security', t); end loop; end $$;

create policy roles_r on roles for select using (is_active_user());
create policy prof_r on profiles for select using (id=auth.uid() or is_active_user());
create policy prof_admin on profiles for all using (is_admin()) with check (is_admin());
create policy prof_self_u on profiles for update using (id=auth.uid()) with check (id=auth.uid());
create function public.profiles_guard() returns trigger language plpgsql security definer set search_path=public as $$
begin if not public.is_admin() and (new.role<>old.role or new.is_active<>old.is_active or new.username<>old.username)
 then raise exception 'yetkisiz'; end if; return new; end $$;
create trigger t_prof_guard before update on profiles for each row execute function profiles_guard();

create policy cat_r on categories for select using (is_active_user() and role_rank(my_role())>=role_rank(min_read_role));
create policy cat_w on categories for all using (is_admin()) with check (is_admin());
create policy fold_r on folders for select using (is_active_user() and (owner_id=auth.uid() or scope='shared' or is_admin()));
create policy fold_w on folders for all using (is_active_user() and (owner_id=auth.uid() or is_admin()))
  with check (is_active_user() and (owner_id=auth.uid() or is_admin()));

create policy doc_r on documents for select using (can_read_doc(documents));
create policy doc_i on documents for insert with check (is_active_user() and owner_id=auth.uid() and (
  scope='personal' or is_admin() or
  (my_role()='teacher' and exists(select 1 from categories c where c.id=category_id and role_rank(my_role())>=role_rank(c.min_upload_role)))));
create policy doc_u on documents for update using (is_active_user() and (is_admin() or owner_id=auth.uid()
  or exists(select 1 from document_permissions p where p.document_id=id and p.user_id=auth.uid() and p.can_write)))
  with check (is_active_user() and (is_admin() or owner_id=auth.uid()
  or exists(select 1 from document_permissions p where p.document_id=id and p.user_id=auth.uid() and p.can_write)));
create policy doc_d on documents for delete using (is_admin()); -- kullanıcılar deleted_at ile çöpe atar

create policy ver_r on document_versions for select using (exists(select 1 from documents d where d.id=document_id and can_read_doc(d)));
create policy ver_i on document_versions for insert with check (created_by=auth.uid()
  and exists(select 1 from documents d where d.id=document_id and (d.owner_id=auth.uid() or is_admin())));
create policy perm_r on document_permissions for select using (user_id=auth.uid() or is_admin()
  or exists(select 1 from documents d where d.id=document_id and d.owner_id=auth.uid()));
create policy perm_w on document_permissions for all using (is_admin() or exists(select 1 from documents d where d.id=document_id and d.owner_id=auth.uid()))
  with check (is_admin() or exists(select 1 from documents d where d.id=document_id and d.owner_id=auth.uid()));
create policy sh_r on shared_files for select using (shared_by=auth.uid() or shared_with=auth.uid() or is_admin());
create policy sh_w on shared_files for all using (shared_by=auth.uid() or is_admin())
  with check (is_active_user() and exists(select 1 from documents d where d.id=document_id and d.owner_id=auth.uid()));
create policy fav_all on favorites for all using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy ann_r on announcements for select using (is_active_user());
create policy ann_w on announcements for all using (is_admin()) with check (is_admin());
create policy log_r on activity_logs for select using (is_admin());
create policy log_i on activity_logs for insert with check (user_id=auth.uid()); -- update/delete politikası yok: değiştirilemez
create policy set_all on user_settings for all using (user_id=auth.uid()) with check (user_id=auth.uid());
-- user_keys: yalnızca sahibi okur/yazar. Başkalarının public key'i bu fonksiyonla alınır.
create policy keys_own on user_keys for all using (user_id=auth.uid()) with check (user_id=auth.uid());
create function public.get_public_key(uid uuid) returns text language sql stable security definer set search_path=public as
$$ select public_key from user_keys where uid is not null and user_id=uid and public.is_active_user() $$;

-- Storage: özel bucket, yol = {shared|personal}/{owner_uid}/{doc_id}/v{n}.bin ; içerik istemcide şifrelenmiş opak veri
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('archive','archive',false,26214400,array['application/octet-stream']) on conflict do nothing;
create policy st_read on storage.objects for select using (bucket_id='archive' and (
  public.is_admin()
  or ((storage.foldername(name))[1]='personal' and (storage.foldername(name))[2]=auth.uid()::text)
  or exists(select 1 from public.documents d where d.storage_path=name and public.can_read_doc(d))
  or exists(select 1 from public.document_versions v join public.documents d on d.id=v.document_id
            where v.storage_path=name and public.can_read_doc(d))));
create policy st_write on storage.objects for insert with check (bucket_id='archive' and public.is_active_user()
  and (storage.foldername(name))[2]=auth.uid()::text
  and ((storage.foldername(name))[1]='personal' or public.my_role() in ('admin','teacher')));
create policy st_del on storage.objects for delete using (bucket_id='archive'
  and (public.is_admin() or (storage.foldername(name))[2]=auth.uid()::text));

-- İlk yönetici: önce Supabase panelinde kullanıcıyı oluşturun, sonra SQL Editor'de:
--   select public.bootstrap_admin('<auth_user_uuid>','yonetici','Ad Soyad');
-- Yalnızca hiç admin yokken çalışır; şifre kodda yer almaz.
create function public.bootstrap_admin(uid uuid, uname text, fname text) returns void
language plpgsql security definer set search_path=public as $$
begin
  if exists(select 1 from profiles where role='admin') then raise exception 'Admin zaten var'; end if;
  insert into profiles(id,username,full_name,role) values (uid,uname,fname,'admin');
end $$;
revoke all on function public.bootstrap_admin(uuid,text,text) from public, anon, authenticated;
