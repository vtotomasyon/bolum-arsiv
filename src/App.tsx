import { useEffect, useState } from 'react'
import { Folder, Lock, Star, Users, Upload, Download, Eye, Trash2, LogOut, Moon, Sun, Search, Home, RotateCcw, ShieldCheck } from 'lucide-react'
import { supabase } from './lib/supabase'
import { createUserKeys, unlockPrivateKey, importPublicKey, validateFile } from './lib/crypto'
import { newDeptKey, wrapDept, unwrapDept, rsaWrapper, deptWrapper, encrypt, decrypt, exportDept } from './lib/vault'

const MIME: Record<string, string> = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', xls: 'application/vnd.ms-excel',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', ppt: 'application/vnd.ms-powerpoint',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation', txt: 'text/plain', csv: 'text/csv', zip: 'application/zip' }
const VIEWABLE = ['application/pdf', 'image/png', 'image/jpeg'] // text/html vb. asla çalıştırılmaz (XSS önlemi)
const fmtSize = (n: number) => n > 1048576 ? (n / 1048576).toLocaleString('tr-TR', { maximumFractionDigits: 1 }) + ' MB' : Math.max(1, Math.round(n / 1024)).toLocaleString('tr-TR') + ' KB'
const fmtDate = (s: string) => new Date(s).toLocaleString('tr-TR', { dateStyle: 'medium', timeStyle: 'short' })
const clean = (s: string) => s.replace(/[,()%*\\]/g, ' ').trim()
const log = (action: string, id?: string) => supabase.from('activity_logs').insert({ action, target_type: 'document', target_id: id })

export default function App() {
  const [session, setSession] = useState<any>(null), [ready, setReady] = useState(false)
  const [profile, setProfile] = useState<any>(undefined), [keyRow, setKeyRow] = useState<any>(undefined), [vault, setVault] = useState<any>(null)
  const [dark, setDark] = useState(() => localStorage.getItem('theme') === 'dark')
  useEffect(() => { document.documentElement.classList.toggle('dark', dark); localStorage.setItem('theme', dark ? 'dark' : 'light') }, [dark])
  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setReady(true) })
    const { data: l } = supabase.auth.onAuthStateChange((_e, s) => { setSession(s); if (!s) { setProfile(undefined); setKeyRow(undefined); setVault(null) } })
    return () => l.subscription.unsubscribe()
  }, [])
  useEffect(() => { if (!session) return; (async () => {
    const { data: p } = await supabase.from('profiles').select('*').eq('id', session.user.id).maybeSingle(); setProfile(p)
    const { data: k } = await supabase.from('user_keys').select('*').maybeSingle(); setKeyRow(k)
  })() }, [session?.user?.id])

  if (!ready || (session && (profile === undefined || keyRow === undefined))) return <div className="p-10 text-center">Yükleniyor…</div>
  if (!session) return <Login />
  if (!profile || !profile.is_active) return <Center><p>Hesabınız etkin değil veya yetkilendirilmemiş.</p><button className="btn mt-4" onClick={() => supabase.auth.signOut()}>Çıkış</button></Center>
  if (!vault) return <KeyGate profile={profile} keyRow={keyRow} onDone={setVault} />
  return <Shell profile={profile} vault={vault} dark={dark} setDark={setDark} />
}
const Center = ({ children }: any) => <div className="grid min-h-screen place-items-center p-4"><div className="card w-full max-w-sm text-center">{children}</div></div>

function Login() {
  const [u, setU] = useState(''), [p, setP] = useState(''), [err, setErr] = useState(''), [busy, setBusy] = useState(false)
  const go = async (e: any) => { e.preventDefault(); setBusy(true); setErr('')
    const { error } = await supabase.auth.signInWithPassword({ email: `${u.trim().toLowerCase()}@bolum.local`, password: p })
    if (error) setErr('Kullanıcı adı veya parola hatalı (çok sayıda denemede geçici olarak engellenirsiniz).'); setBusy(false) }
  return <Center><ShieldCheck className="mx-auto mb-2 h-10 w-10 text-blue-700" /><h1 className="mb-4 text-xl font-semibold">Bölüm Arşivi</h1>
    <form onSubmit={go} className="space-y-3 text-left"><input className="inp" placeholder="Kullanıcı adı" value={u} onChange={e => setU(e.target.value)} autoComplete="username" />
      <input className="inp" type="password" placeholder="Parola" value={p} onChange={e => setP(e.target.value)} autoComplete="current-password" />
      {err && <p className="text-sm text-red-600">{err}</p>}<button className="btn w-full justify-center" disabled={busy}>Giriş yap</button></form></Center>
}

function KeyGate({ profile, keyRow, onDone }: any) {
  const [pass, setPass] = useState(''), [pass2, setPass2] = useState(''), [err, setErr] = useState(''), [busy, setBusy] = useState(false)
  const creating = !keyRow
  const go = async (e: any) => { e.preventDefault(); setErr(''); setBusy(true)
    try {
      if (creating) {
        if (pass.length < 12 || pass !== pass2) throw new Error('Şifreleme parolası en az 12 karakter olmalı ve eşleşmeli')
        const k = await createUserKeys(pass); let D = null, wrapped = null
        const pub = await importPublicKey(k.public_key)
        if (profile.role === 'admin') { const { data: ex } = await supabase.rpc('dept_key_exists'); if (!ex) { D = await newDeptKey(); wrapped = await wrapDept(D, pub) } }
        const { error } = await supabase.from('user_keys').insert({ ...k, wrapped_dept_key: wrapped }); if (error) throw error
        onDone({ priv: await unlockPrivateKey(pass, k), pub, D })
      } else {
        const priv = await unlockPrivateKey(pass, keyRow)
        onDone({ priv, pub: await importPublicKey(keyRow.public_key), D: keyRow.wrapped_dept_key ? await unwrapDept(keyRow.wrapped_dept_key, priv) : null })
      }
    } catch (x: any) { setErr(creating ? x.message : 'Şifreleme parolası yanlış') } setBusy(false) }
  return <Center><Lock className="mx-auto mb-2 h-10 w-10 text-blue-700" />
    <h1 className="mb-2 text-lg font-semibold">{creating ? 'Şifreleme parolası oluştur' : 'Şifreleme parolasını gir'}</h1>
    <p className="mb-3 text-sm text-slate-500">Dosyalar tarayıcınızda şifrelenir. Bu parola kaybolursa kişisel dosyalarınız kurtarılamaz; yöneticiniz de sıfırlayamaz.</p>
    <form onSubmit={go} className="space-y-3 text-left"><input className="inp" type="password" value={pass} onChange={e => setPass(e.target.value)} placeholder="Şifreleme parolası" />
      {creating && <input className="inp" type="password" value={pass2} onChange={e => setPass2(e.target.value)} placeholder="Tekrar" />}
      {err && <p className="text-sm text-red-600">{err}</p>}<button className="btn w-full justify-center" disabled={busy}>{busy ? 'İşleniyor…' : 'Devam'}</button></form>
    <button className="mt-3 text-xs underline" onClick={() => supabase.auth.signOut()}>Çıkış</button></Center>
}

function Shell({ profile, vault, dark, setDark }: any) {
  const [cats, setCats] = useState<any[]>([]), [view, setView] = useState('home'), [q, setQ] = useState('')
  useEffect(() => { supabase.from('categories').select('*').order('sort').then(({ data }) => setCats(data ?? [])) }, [])
  const nav = (id: string, label: string, Icon: any) => <button key={id} onClick={() => setView(id)}
    className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-sm ${view === id ? 'bg-blue-700 text-white' : 'hover:bg-slate-200 dark:hover:bg-slate-800'}`}><Icon className="h-4 w-4 shrink-0" />{label}</button>
  return <div className="flex min-h-screen flex-col md:flex-row">
    <aside className="space-y-1 border-b border-slate-200 bg-white p-3 md:w-64 md:border-b-0 md:border-r dark:border-slate-800 dark:bg-slate-900">
      <div className="mb-2 px-3 font-semibold text-blue-800 dark:text-blue-300">Bölüm Arşivi</div>
      {nav('home', 'Ana Sayfa', Home)}{cats.map(c => nav('cat:' + c.id, c.name, Folder))}
      {nav('personal', 'Kişisel Bulut Alanım', Lock)}{nav('favs', 'Favorilerim', Star)}{nav('trash', 'Çöp Kutusu', Trash2)}
      {profile.role === 'admin' && nav('users', 'Kullanıcı Yönetimi', Users)}
      <div className="flex items-center justify-between px-3 pt-3 text-xs"><span>{profile.full_name || profile.username}</span>
        <span className="flex gap-2"><button onClick={() => setDark(!dark)}>{dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}</button>
          <button onClick={() => supabase.auth.signOut()}><LogOut className="h-4 w-4" /></button></span></div>
    </aside>
    <main className="flex-1 space-y-4 p-4">
      {view !== 'users' && <div className="relative"><Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
        <input className="inp pl-9" placeholder="Arşivde ara (ad, açıklama, ders, etiket)…" value={q} onChange={e => setQ(e.target.value)} /></div>}
      {view === 'users' ? <Admin vault={vault} /> : <Docs key={view} view={view} q={q} cats={cats} profile={profile} vault={vault} />}
    </main></div>
}

function Docs({ view, q, cats, profile, vault }: any) {
  const [docs, setDocs] = useState<any[]>([]), [limit, setLimit] = useState(30), [msg, setMsg] = useState(''), [tick, setTick] = useState(0)
  const [meta, setMeta] = useState({ description: '', tags: '', course: '', year: '' })
  const catId = view.startsWith('cat:') ? view.slice(4) : null
  const scope = view === 'personal' ? 'personal' : 'shared'
  useEffect(() => { (async () => {
    let s = supabase.from('documents').select(view === 'favs' ? '*, favorites!inner(user_id)' : '*, favorites(user_id)').order('created_at', { ascending: false }).range(0, limit - 1)
    s = view === 'trash' ? s.not('deleted_at', 'is', null) : s.is('deleted_at', null)
    if (catId) s = s.eq('scope', 'shared').eq('category_id', catId)
    else if (view === 'personal') s = s.eq('scope', 'personal').eq('owner_id', profile.id)
    else if (view === 'home') s = s.eq('scope', 'shared')
    const t = clean(q); if (t) s = s.or(`title.ilike.%${t}%,description.ilike.%${t}%,course.ilike.%${t}%,school_year.ilike.%${t}%`)
    const { data, error } = await s; if (error) setMsg(error.message); else setDocs(data ?? [])
  })() }, [view, q, limit, tick])
  const wrapperFor = (d: any) => d.scope === 'personal' ? rsaWrapper(vault.pub, vault.priv) : vault.D ? deptWrapper(vault.D) : null
  async function upload(files: File[]) {
    const w = scope === 'personal' ? rsaWrapper(vault.pub, vault.priv) : vault.D ? deptWrapper(vault.D) : null
    if (!w) return setMsg('Ortak anahtar henüz yönetici tarafından onaylanmadı.')
    const out: string[] = []
    for (const f of files) {
      const err = validateFile(f); if (err) { out.push(`${f.name}: ${err}`); continue }
      const ext = f.name.split('.').pop()!.toLowerCase(), id = crypto.randomUUID(), path = `${scope}/${profile.id}/${id}/v1.bin`
      const e = await encrypt(f, w)
      const up = await supabase.storage.from('archive').upload(path, e.blob, { contentType: 'application/octet-stream' })
      if (up.error) { out.push(`${f.name}: yüklenemedi (yetki/limit)`); continue }
      const ins = await supabase.from('documents').insert({ id, scope, category_id: scope === 'shared' ? catId : null, title: f.name, description: meta.description || null,
        tags: meta.tags.split(',').map(x => x.trim()).filter(Boolean), course: meta.course || null, school_year: meta.year || null, doc_type: ext,
        mime: MIME[ext], size_bytes: f.size, storage_path: path, enc_iv: e.enc_iv, enc_wrapped_key: e.enc_wrapped_key })
      if (ins.error) { await supabase.storage.from('archive').remove([path]); out.push(`${f.name}: ${ins.error.message}`); continue }
      log('yukle', id)
    }
    setMsg(out.join(' • ')); setTick(t => t + 1)
  }
  async function open(d: any, download: boolean) {
    try {
      const w = wrapperFor(d); if (!w) return setMsg('Anahtar yok')
      const { data, error } = await supabase.storage.from('archive').download(d.storage_path); if (error) throw error
      const plain = await decrypt(await data.arrayBuffer(), d.enc_iv, d.enc_wrapped_key, w)
      const viewable = !download && VIEWABLE.includes(d.mime)
      const url = URL.createObjectURL(new Blob([plain], { type: viewable ? d.mime : 'application/octet-stream' }))
      if (viewable) window.open(url, '_blank', 'noopener'); else { const a = document.createElement('a'); a.href = url; a.download = d.title; a.click() }
      setTimeout(() => URL.revokeObjectURL(url), 60000); log(download ? 'indir' : 'goruntule', d.id)
    } catch { setMsg('Dosya açılamadı (yetki veya anahtar hatası).') }
  }
  const fav = async (d: any) => { d.favorites?.length ? await supabase.from('favorites').delete().eq('document_id', d.id) : await supabase.from('favorites').insert({ document_id: d.id }); setTick(t => t + 1) }
  const trash = async (d: any, restore = false) => { await supabase.from('documents').update({ deleted_at: restore ? null : new Date().toISOString(), updated_at: new Date().toISOString() }).eq('id', d.id); log(restore ? 'geri_al' : 'sil', d.id); setTick(t => t + 1) }
  const purge = async (d: any) => { if (!confirm('Kalıcı silinsin mi?')) return; await supabase.storage.from('archive').remove([d.storage_path]); await supabase.from('documents').delete().eq('id', d.id); setTick(t => t + 1) }
  const title = view === 'home' ? 'Son yüklenenler' : view === 'personal' ? 'Kişisel Bulut Alanım' : view === 'favs' ? 'Favorilerim' : view === 'trash' ? 'Çöp Kutusu' : cats.find((c: any) => c.id === catId)?.name
  const canUpload = view === 'personal' || (catId && ['admin', 'teacher'].includes(profile.role))
  return <div className="space-y-4"><h2 className="text-lg font-semibold">{title}</h2>
    {msg && <div className="card text-sm text-amber-700">{msg}</div>}
    {canUpload && <div className="card space-y-2" onDragOver={e => e.preventDefault()} onDrop={e => { e.preventDefault(); upload([...e.dataTransfer.files]) }}>
      <div className="grid gap-2 sm:grid-cols-4">
        <input className="inp" placeholder="Açıklama" value={meta.description} onChange={e => setMeta({ ...meta, description: e.target.value })} />
        <input className="inp" placeholder="Etiketler (virgülle)" value={meta.tags} onChange={e => setMeta({ ...meta, tags: e.target.value })} />
        <input className="inp" placeholder="Ders" value={meta.course} onChange={e => setMeta({ ...meta, course: e.target.value })} />
        <input className="inp" placeholder="Eğitim yılı (2025-2026)" value={meta.year} onChange={e => setMeta({ ...meta, year: e.target.value })} /></div>
      <label className="btn cursor-pointer"><Upload className="h-4 w-4" /> Dosya seç veya buraya sürükle (en fazla 25 MB, şifrelenerek yüklenir)
        <input type="file" multiple hidden onChange={e => { upload([...(e.target.files ?? [])]); e.target.value = '' }} /></label></div>}
    {docs.length === 0 ? <div className="card text-center text-slate-500">Bu alanda henüz belge yok.</div> :
      <div className="space-y-2">{docs.map(d => <div key={d.id} className="card flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0"><div className="truncate font-medium">{d.title}</div>
          <div className="text-xs text-slate-500">{fmtSize(d.size_bytes)} • {fmtDate(d.created_at)}{d.course && ` • ${d.course}`}{d.school_year && ` • ${d.school_year}`}{d.tags?.length ? ` • ${d.tags.join(', ')}` : ''}</div>
          {d.description && <div className="text-sm">{d.description}</div>}</div>
        <div className="flex gap-1">
          {view === 'trash' ? <><button className="btn2" onClick={() => trash(d, true)}><RotateCcw className="h-3 w-3" />Geri al</button>
            {profile.role === 'admin' && <button className="btn2" onClick={() => purge(d)}>Kalıcı sil</button>}</> : <>
            {VIEWABLE.includes(d.mime) && <button className="btn2" onClick={() => open(d, false)}><Eye className="h-3 w-3" />Aç</button>}
            <button className="btn2" onClick={() => open(d, true)}><Download className="h-3 w-3" />İndir</button>
            <button className="btn2" onClick={() => fav(d)}><Star className={`h-3 w-3 ${d.favorites?.length ? 'fill-yellow-400' : ''}`} /></button>
            {(d.owner_id === profile.id || profile.role === 'admin') && <button className="btn2" onClick={() => trash(d)}><Trash2 className="h-3 w-3" /></button>}</>}
        </div></div>)}
        {docs.length >= limit && <button className="btn2" onClick={() => setLimit(limit + 30)}>Daha fazla</button>}</div>}</div>
}

function Admin({ vault }: any) {
  const [users, setUsers] = useState<any[]>([]), [pending, setPending] = useState<any[]>([]), [msg, setMsg] = useState(''), [tick, setTick] = useState(0)
  const [f, setF] = useState({ username: '', full_name: '', password: '', role: 'teacher' })
  useEffect(() => { supabase.from('profiles').select('*').order('created_at').then(({ data }) => setUsers(data ?? []))
    supabase.rpc('pending_key_requests').then(({ data }) => setPending(data ?? [])) }, [tick])
  const call = async (body: any) => { const { data, error } = await supabase.functions.invoke('admin-users', { body }); setMsg(error || data?.error ? (data?.error ?? 'İşlem başarısız') : 'Tamam'); setTick(t => t + 1) }
  const grant = async (p: any) => { if (!vault.D) return setMsg('Ortak anahtarınız yok'); const { error } = await supabase.rpc('grant_dept_key', { uid: p.user_id, wrapped: await wrapDept(vault.D, await importPublicKey(p.public_key)) }); setMsg(error ? error.message : 'Anahtar onaylandı'); setTick(t => t + 1) }
  const recovery = async () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([await exportDept(vault.D)])); a.download = 'KURTARMA-ANAHTARI.txt'; a.click() }
  return <div className="space-y-4"><h2 className="text-lg font-semibold">Kullanıcı Yönetimi</h2>{msg && <div className="card text-sm">{msg}</div>}
    <div className="card grid gap-2 sm:grid-cols-5"><input className="inp" placeholder="kullanıcı adı" value={f.username} onChange={e => setF({ ...f, username: e.target.value })} />
      <input className="inp" placeholder="Ad Soyad" value={f.full_name} onChange={e => setF({ ...f, full_name: e.target.value })} />
      <input className="inp" type="password" placeholder="Geçici parola (≥10)" value={f.password} onChange={e => setF({ ...f, password: e.target.value })} />
      <select className="inp" value={f.role} onChange={e => setF({ ...f, role: e.target.value })}><option value="teacher">Öğretmen</option><option value="user">Standart</option><option value="admin">Yönetici</option></select>
      <button className="btn justify-center" onClick={() => call({ action: 'create', ...f })}>Kullanıcı ekle</button></div>
    {pending.length > 0 && <div className="card space-y-2"><div className="text-sm font-medium">Ortak arşiv anahtarı bekleyenler</div>
      {pending.map(p => <div key={p.user_id} className="flex items-center justify-between text-sm">{p.username}<button className="btn2" onClick={() => grant(p)}>Onayla</button></div>)}</div>}
    {users.map(u => <div key={u.id} className="card flex flex-wrap items-center justify-between gap-2 text-sm">
      <div>{u.full_name || u.username} <span className="text-slate-500">({u.username}) • {u.role}{!u.is_active && ' • devre dışı'}</span></div>
      <div className="flex gap-1"><select className="btn2" value={u.role} onChange={async e => { await supabase.from('profiles').update({ role: e.target.value }).eq('id', u.id); setTick(t => t + 1) }}>
        <option value="admin">admin</option><option value="teacher">teacher</option><option value="user">user</option></select>
        <button className="btn2" onClick={() => { const p = prompt('Yeni geçici parola (≥10)'); if (p) call({ action: 'reset', id: u.id, password: p }) }}>Parola sıfırla</button>
        <button className="btn2" onClick={() => call({ action: 'active', id: u.id, active: !u.is_active })}>{u.is_active ? 'Devre dışı bırak' : 'Etkinleştir'}</button></div></div>)}
    {vault.D && <button className="btn2" onClick={recovery}>Ortak anahtar kurtarma dosyasını indir (güvenli yerde saklayın)</button>}</div>
}
