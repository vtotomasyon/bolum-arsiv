# Bölüm Arşivi (Endüstriyel Otomasyon Teknolojileri)
React + TypeScript + Vite + Tailwind • Supabase (Auth, Postgres+RLS, Storage, Edge Function) • GitHub Pages.
Dosyalar tarayıcıda AES-256-GCM ile şifrelenir; sunucu yalnızca şifreli veri görür.

## Kurulum (PowerShell)
1. https://supabase.com → yeni proje. Auth → Providers → Email: **"Allow new users to sign up" KAPALI**, "Confirm email" kapalı olabilir, minimum parola uzunluğu 10.
2. Supabase CLI ile (proje klasöründe):
   `npm install`
   `npx supabase login`
   `npx supabase init`   (sorulursa VS Code ayarlarını atla)
   `npx supabase link --project-ref PROJE_REF`
   `npx supabase db push`
   `npx supabase functions deploy admin-users`
3. İlk yönetici: Dashboard → Authentication → Users → "Add user" (e-posta: `yonetici@bolum.local`, güçlü parola, Auto Confirm). Kullanıcının UUID'sini kopyala, SQL Editor'de:
   `select public.bootstrap_admin('UUID','yonetici','Ad Soyad');`
4. `Copy-Item .env.example .env` → URL ve **anon** anahtarı yaz. `npm run dev`
5. Admin ile giriş → şifreleme parolası oluştur (ortak bölüm anahtarı otomatik üretilir) → "Kurtarma dosyasını indir" ve çevrimdışı sakla.
6. Kullanıcıları ekle. Her kullanıcı ilk girişte şifreleme parolası belirler; admin "Kullanıcı Yönetimi"nde **anahtarı onaylar**, ardından ortak arşive erişir.

## Yayınlama
`git init; git add .; git commit -m "ilk sürüm"; git branch -M main; git remote add origin https://github.com/KULLANICI/REPO.git; git push -u origin main`
GitHub → Settings → Secrets and variables → Actions: `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`. Settings → Pages → Source: **GitHub Actions**.
Supabase → Auth → URL Configuration → Site URL'e Pages adresini yaz. (Not: `package-lock.json`'ı da commit'le.)

## Güvenlik notları / limitler
- Yetkilendirme RLS + storage politikalarıyla veritabanında uygulanır; service_role anahtarı yalnızca Edge Function'da (Supabase sırrı) bulunur.
- Parola/şifreleme parolası kaybı: kişisel dosyalar kurtarılamaz. Ortak anahtar için kurtarma dosyası şart.
- İçerik şifreli olduğundan içerik araması ve sunucu tarafı virüs taraması yoktur; yalnızca tür/boyut kontrolü ve güvenli açma (yalnızca PDF/PNG/JPG önizlenir).
- Ücretsiz Supabase: ~1 GB depolama, 500 MB veritabanı, bir süre işlem olmazsa proje duraklatılabilir; ücretsiz planda otomatik yedek yoktur → düzenli `npx supabase db dump -f yedek.sql` ve Storage'ı indirme (dosyalar zaten şifreli).
- Giriş denemeleri Supabase Auth'un yerleşik hız sınırıyla kısıtlanır.
