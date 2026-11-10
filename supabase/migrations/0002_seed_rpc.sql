insert into public.categories(name,slug,min_read_role,min_upload_role,sort) values
('Yıllık Planlar','yillik-planlar','user','teacher',1),('Ders Kitapları','ders-kitaplari','user','teacher',2),
('Ders Materyalleri','ders-materyalleri','user','teacher',3),('Sınav Arşivi','sinav-arsivi','teacher','teacher',4),
('Zümre Evrakları','zumre-evraklari','teacher','teacher',5),('Kulüp Evrakları','kulup-evraklari','teacher','teacher',6),
('Projeler ve Etkinlikler','projeler-etkinlikler','user','teacher',7),('Atölye ve Laboratuvar','atolye-laboratuvar','user','teacher',8),
('İş Sağlığı ve Güvenliği','isg','user','teacher',9),('Ortak Dokümanlar','ortak-dokumanlar','user','teacher',10)
on conflict do nothing;

create policy doc_trash_r on public.documents for select using (deleted_at is not null and (owner_id=auth.uid() or public.is_admin()));

create function public.dept_key_exists() returns boolean language sql stable security definer set search_path=public as
$$ select exists(select 1 from user_keys where wrapped_dept_key is not null) $$;
create function public.pending_key_requests() returns table(user_id uuid, username text, public_key text)
language sql stable security definer set search_path=public as
$$ select k.user_id, p.username, k.public_key from user_keys k join profiles p on p.id=k.user_id
   where k.wrapped_dept_key is null and public.is_admin() and p.is_active $$;
create function public.grant_dept_key(uid uuid, wrapped text) returns void language plpgsql security definer set search_path=public as
$$ begin if not public.is_admin() then raise exception 'yetkisiz'; end if;
   update user_keys set wrapped_dept_key=wrapped where user_id=uid;
   insert into activity_logs(user_id,action,target_type,target_id) values (auth.uid(),'anahtar_onayi','user',uid::text); end $$;
revoke all on function public.dept_key_exists(), public.pending_key_requests(), public.grant_dept_key(uuid,text) from public, anon;
grant execute on function public.dept_key_exists(), public.pending_key_requests(), public.grant_dept_key(uuid,text) to authenticated;
