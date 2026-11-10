import { createClient } from 'npm:@supabase/supabase-js@2'
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, content-type, apikey, x-client-info' }
const J = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } })
Deno.serve(async req => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  const url = Deno.env.get('SUPABASE_URL')!
  const caller = createClient(url, Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: req.headers.get('Authorization') ?? '' } } })
  const { data: { user } } = await caller.auth.getUser()
  const db = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)
  const { data: me } = user ? await db.from('profiles').select('role,is_active').eq('id', user.id).single() : { data: null }
  if (!me || me.role !== 'admin' || !me.is_active) return J({ error: 'Yetkisiz' }, 403)
  const b = await req.json().catch(() => ({}))
  const log = (action: string, id: string) => db.from('activity_logs').insert({ user_id: user!.id, action, target_type: 'user', target_id: id })
  if (b.action === 'create') {
    if (!/^[a-z0-9._-]{3,32}$/.test(b.username ?? '') || (b.password ?? '').length < 10 || !['admin', 'teacher', 'user'].includes(b.role))
      return J({ error: 'Geçersiz bilgi (parola en az 10 karakter)' }, 400)
    const { data, error } = await db.auth.admin.createUser({ email: `${b.username}@bolum.local`, password: b.password, email_confirm: true })
    if (error) return J({ error: error.message }, 400)
    const { error: pe } = await db.from('profiles').insert({ id: data.user.id, username: b.username, full_name: b.full_name ?? '', role: b.role })
    if (pe) { await db.auth.admin.deleteUser(data.user.id); return J({ error: pe.message }, 400) }
    await log('kullanici_olustur', data.user.id); return J({ ok: true })
  }
  if (b.action === 'reset') {
    if ((b.password ?? '').length < 10) return J({ error: 'Parola en az 10 karakter' }, 400)
    const { error } = await db.auth.admin.updateUserById(b.id, { password: b.password })
    await log('sifre_sifirla', b.id); return error ? J({ error: error.message }, 400) : J({ ok: true })
  }
  if (b.action === 'active') {
    if (b.id === user!.id) return J({ error: 'Kendinizi devre dışı bırakamazsınız' }, 400)
    await db.from('profiles').update({ is_active: !!b.active }).eq('id', b.id)
    await db.auth.admin.updateUserById(b.id, { ban_duration: b.active ? 'none' : '876000h' })
    await log(b.active ? 'kullanici_aktif' : 'kullanici_pasif', b.id); return J({ ok: true })
  }
  return J({ error: 'Bilinmeyen işlem' }, 400)
})
