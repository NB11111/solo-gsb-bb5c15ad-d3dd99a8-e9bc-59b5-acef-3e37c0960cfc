/**
 * 加密备份：基于 Web Crypto（SubtleCrypto）的口令加密导出/导入。
 *
 * 信封（版本化 JSON）：
 *   {
 *     "format": "ipv4-subnet-planner/encrypted-backup",
 *     "version": 1,
 *     "kdf": "PBKDF2",
 *     "digest": "SHA-256",
 *     "iterations": 200000,
 *     "cipher": "AES-GCM-256",
 *     "salt": "<Base64, 16 字节>",
 *     "iv": "<Base64, 12 字节>",
 *     "ciphertext": "<Base64, AES-GCM 密文（含认证标签）>"
 *   }
 *
 * 安全约束：
 * - salt / iv 每次导出均用 crypto.getRandomValues 重新随机生成；
 * - 口令经 PBKDF2-SHA-256 200000 次迭代派生 AES-GCM 256 位密钥；
 * - CryptoKey 始终 nonExtractable，仅在单次加/解密调用期间存在于内存；
 * - 不持久化口令、不持久化派生密钥（本模块不触碰任何存储）。
 */
import { Plan, parsePlanJson, serializePlan } from './model';

export const ENCRYPTED_BACKUP_FORMAT = 'ipv4-subnet-planner/encrypted-backup';
export const ENCRYPTED_BACKUP_VERSION = 1 as const;
export const PBKDF2_ITERATIONS = 200_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_BYTES = 32; // AES-256

export interface EncryptedBackup {
  format: typeof ENCRYPTED_BACKUP_FORMAT;
  version: 1;
  kdf: 'PBKDF2';
  digest: 'SHA-256';
  iterations: 200000;
  cipher: 'AES-GCM-256';
  salt: string;
  iv: string;
  ciphertext: string;
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('当前环境不支持 Web Crypto（SubtleCrypto），无法进行加密备份');
  return s;
}

function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/**
 * 严格解码 Base64：拒绝空白/缺失填充/URL 安全变体等任何非标准字母表输入，
 * 并要求解码后字节数与 expectedLength 完全一致。
 */
function base64ToBytes(value: unknown, field: string, expectedLength: number): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`加密备份字段非法：${field} 必须为非空 Base64 字符串`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error(`加密备份字段非法：${field} 不是合法 Base64`);
  }
  let binary: string;
  try {
    binary = atob(value);
  } catch {
    throw new Error(`加密备份字段非法：${field} 不是合法 Base64`);
  }
  // atob 对宽松输入可能放行，这里再核对一次编码往返与长度。
  if (btoa(binary) !== value || binary.length !== expectedLength) {
    throw new Error(
      `加密备份字段非法：${field} 长度必须为 ${expectedLength} 字节`,
    );
  }
  const bytes = new Uint8Array(expectedLength);
  for (let i = 0; i < expectedLength; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** PBKDF2-SHA-256 派生不可导出的 AES-GCM 256 位密钥。密钥在 importKey 后无法再读出原始字节。 */
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const baseKey = await subtle().importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: KEY_BYTES * 8 },
    false, // 不允许导出派生密钥
    ['encrypt', 'decrypt'],
  );
}

/**
 * 导出加密备份：随机 salt/iv + PBKDF2 派生密钥 + AES-GCM 加密当前 Plan 的序列化 JSON。
 * 口令为空时直接拒绝（调用方也应先做表单校验）。
 */
export async function encryptPlan(plan: Plan, password: string): Promise<EncryptedBackup> {
  if (!password) throw new Error('加密口令不能为空');
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = await deriveKey(password, salt);
  const ciphertext = await subtle().encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(serializePlan(plan)),
  );
  return {
    format: ENCRYPTED_BACKUP_FORMAT,
    version: ENCRYPTED_BACKUP_VERSION,
    kdf: 'PBKDF2',
    digest: 'SHA-256',
    iterations: PBKDF2_ITERATIONS,
    cipher: 'AES-GCM-256',
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
  };
}

/** 仅解析信封外壳：字段齐全、Base64 合法、版本与算法参数受支持；不做任何解密。 */
export function parseEnvelope(text: string): {
  envelope: EncryptedBackup;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
} {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new Error('加密备份解析失败：文件不是合法 JSON');
  }
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('加密备份格式错误：顶层应为对象');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.format !== ENCRYPTED_BACKUP_FORMAT) {
    throw new Error('不是本工具的加密备份信封（format 不匹配），已拒绝导入');
  }
  if (obj.version !== ENCRYPTED_BACKUP_VERSION) {
    throw new Error(
      `加密备份版本不受支持：收到 v${String(obj.version)}，本工具仅支持 v${ENCRYPTED_BACKUP_VERSION}`,
    );
  }
  if (
    obj.kdf !== 'PBKDF2' ||
    obj.digest !== 'SHA-256' ||
    obj.cipher !== 'AES-GCM-256' ||
    obj.iterations !== PBKDF2_ITERATIONS
  ) {
    throw new Error('加密备份算法参数不受支持（要求 PBKDF2-SHA-256 / 200000 次 / AES-GCM-256）');
  }
  const salt = base64ToBytes(obj.salt, 'salt', SALT_BYTES);
  const iv = base64ToBytes(obj.iv, 'iv', IV_BYTES);
  if (typeof obj.ciphertext !== 'string' || obj.ciphertext.length === 0) {
    throw new Error('加密备份字段非法：ciphertext 必须为非空 Base64 字符串');
  }
  let ciphertext: Uint8Array;
  try {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(obj.ciphertext) || obj.ciphertext.length % 4 !== 0) {
      throw new Error('bad base64');
    }
    const binary = atob(obj.ciphertext);
    if (binary.length === 0 || btoa(binary) !== obj.ciphertext) throw new Error('bad base64');
    ciphertext = Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
  } catch {
    throw new Error('加密备份字段非法：ciphertext 不是合法 Base64');
  }
  return { envelope: obj as unknown as EncryptedBackup, salt, iv, ciphertext };
}

/**
 * 解密并校验加密备份：
 * 1. parseEnvelope 校验信封（结构/版本/Base64）；
 * 2. PBKDF2 派生密钥后 AES-GCM 认证解密——口令错误或密文被篡改都会在此被 GCM 标签拒绝；
 * 3. 明文必须是 UTF-8 JSON 且通过现有 Plan 完整校验。
 * 任何一步失败都抛出带中文信息的 Error，调用方保证不改动当前 Plan。
 */
export async function decryptPlan(text: string, password: string): Promise<Plan> {
  const { salt, iv, ciphertext } = parseEnvelope(text);
  const key = await deriveKey(password, salt);
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await subtle().decrypt({ name: 'AES-GCM', iv }, key, ciphertext),
    );
  } catch {
    // AES-GCM 认证失败：口令错误与密文/标签篡改在密码学上不可区分，统一拒绝。
    throw new Error('解密失败：口令错误或密文已被篡改');
  }
  let json: string;
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(plain);
  } catch {
    throw new Error('解密失败：口令错误或密文已被篡改（明文不是合法 UTF-8）');
  }
  // 复用现有 Plan 解析与完整校验（格式、对齐、重叠、越界、容量一致性）。
  return parsePlanJson(json);
}

export function serializeEnvelope(backup: EncryptedBackup): string {
  return JSON.stringify(backup, null, 2);
}
