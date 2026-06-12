/**
 * @module crypto/decrypt
 * @description Функции для расшифровки данных.
 */
import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY = Buffer.from(process.env.TOTP_ENC_KEY, 'hex');

/**
 * Decrypts a ciphertext string encrypted with AES-256-GCM.
 *
 * @param {string} data - The encrypted string formatted as 'iv:tag:encrypted' in hexadecimal.
 * @returns {string} The decrypted plaintext string.
 * @throws {Error} Throws an error if decryption fails, such as authentication tag mismatch or invalid key/iv.
 */
export function decrypt(data) {
  const [ivHex, tagHex, encryptedHex] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
    'utf8',
  );
}
