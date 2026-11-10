// İstemci taraflı şifreleme (WebCrypto). Sunucu yalnızca şifreli veri + SARILMIŞ anahtar görür.
// Parola -> PBKDF2(600k) -> AES-GCM anahtarı -> RSA-OAEP özel anahtarı sarar.
// Her dosya: rastgele AES-256-GCM anahtarı; bu anahtar sahibin (veya bölüm) RSA public key'iyle sarılır.
const enc = new TextEncoder();
export const b64 = (u: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(u as ArrayBuffer)));
export const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function kekFromPassword(password: string, salt: Uint8Array, iters: number) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iters, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
export async function createUserKeys(password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iters = 600_000;
  const kek = await kekFromPassword(password, salt, iters);
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072,
    publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['wrapKey', 'unwrapKey']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  return { kdf_salt: b64(salt), kdf_iters: iters, wrapped_private_key: `${b64(iv)}.${b64(wrapped)}`,
    public_key: b64(await crypto.subtle.exportKey('spki', pair.publicKey)) };
}
export async function unlockPrivateKey(password: string, row: { kdf_salt: string; kdf_iters: number; wrapped_private_key: string }) {
  const kek = await kekFromPassword(password, unb64(row.kdf_salt), row.kdf_iters);
  const [iv, ct] = row.wrapped_private_key.split('.');
  const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, kek, unb64(ct));
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['unwrapKey']);
}
export const importPublicKey = (spkiB64: string) =>
  crypto.subtle.importKey('spki', unb64(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['wrapKey']);

export async function encryptFile(file: File, pub: CryptoKey) {
  const fileKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, await file.arrayBuffer());
  const wrapped = await crypto.subtle.wrapKey('raw', fileKey, pub, { name: 'RSA-OAEP' });
  return { blob: new Blob([ct], { type: 'application/octet-stream' }), enc_iv: b64(iv), enc_wrapped_key: b64(wrapped) };
}
export async function decryptFile(ct: ArrayBuffer, ivB64: string, wrappedB64: string, priv: CryptoKey) {
  const fileKey = await crypto.subtle.unwrapKey('raw', unb64(wrappedB64), priv, { name: 'RSA-OAEP' },
    { name: 'AES-GCM' }, false, ['decrypt']);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, fileKey, ct);
}
// Şifrelemeden ÖNCE istemcide doğrulama (sunucu opak veri gördüğü için içerik taraması yapamaz)
export const ALLOWED = ['pdf','doc','docx','xls','xlsx','ppt','pptx','png','jpg','jpeg','txt','zip','csv'];
export const MAX_BYTES = 25 * 1024 * 1024;
export function validateFile(f: File) {
  const ext = f.name.split('.').pop()?.toLowerCase() ?? '';
  if (!ALLOWED.includes(ext)) return `İzin verilmeyen dosya türü: .${ext}`;
  if (f.size > MAX_BYTES) return 'Dosya 25 MB sınırını aşıyor';
  return null;
}
