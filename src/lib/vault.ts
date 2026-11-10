import { b64, unb64 } from './crypto'
const RSA = { name: 'RSA-OAEP' }
export const newDeptKey = () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
export const wrapDept = async (D: CryptoKey, pub: CryptoKey) => b64(await crypto.subtle.wrapKey('raw', D, pub, RSA))
export const unwrapDept = (w: string, priv: CryptoKey) =>
  crypto.subtle.unwrapKey('raw', unb64(w), priv, RSA, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
export const exportDept = async (D: CryptoKey) => b64(await crypto.subtle.exportKey('raw', D))
export type Wrapper = { wrap: (k: CryptoKey) => Promise<string>; unwrap: (w: string) => Promise<CryptoKey> }
export const rsaWrapper = (pub: CryptoKey, priv: CryptoKey): Wrapper => ({
  wrap: async k => b64(await crypto.subtle.wrapKey('raw', k, pub, RSA)),
  unwrap: w => crypto.subtle.unwrapKey('raw', unb64(w), priv, RSA, { name: 'AES-GCM' }, false, ['decrypt']) })
export const deptWrapper = (D: CryptoKey): Wrapper => ({
  wrap: async k => { const iv = crypto.getRandomValues(new Uint8Array(12));
    return b64(iv) + '.' + b64(await crypto.subtle.wrapKey('raw', k, D, { name: 'AES-GCM', iv })) },
  unwrap: w => { const [iv, ct] = w.split('.');
    return crypto.subtle.unwrapKey('raw', unb64(ct), D, { name: 'AES-GCM', iv: unb64(iv) }, { name: 'AES-GCM' }, false, ['decrypt']) } })
export async function encrypt(file: File, w: Wrapper) {
  const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, await file.arrayBuffer())
  return { blob: new Blob([ct], { type: 'application/octet-stream' }), enc_iv: b64(iv), enc_wrapped_key: await w.wrap(k) }
}
export async function decrypt(ct: ArrayBuffer, iv: string, wrapped: string, w: Wrapper) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, await w.unwrap(wrapped), ct)
}
