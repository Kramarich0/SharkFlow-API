/**
 * @module crypto/encrypt
 /**
  * @module crypto/encrypt
  * @description Provides cryptographic utilities for data encryption using AES-256-GCM.
  */
 import crypto from 'crypto';

 /** @constant {string} ALGORITHM The AES-GCM cipher algorithm variant. */
 const ALGORITHM = 'aes-256-gcm';

 /** @constant {Buffer} KEY The cryptographic key derived from the TOTP_ENC_KEY environment variable. */
 const KEY = Buffer.from(process.env.TOTP_ENC_KEY, 'hex');

 /**
  * Encrypts a plaintext string using AES-256-GCM authenticated encryption.
  * @param {string} text - The plaintext string to encrypt.
  * @returns {string} A colon-delimited string containing the hex-encoded initialization vector, authentication tag, and ciphertext.
  */
 export function encrypt(text) {
   const iv = crypto.randomBytes(12);
   const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
   const encrypted = Buffer.concat([
     cipher.update(text, 'utf8'),
     cipher.final(),
   ]);
   const tag = cipher.getAuthTag();
   return (
     iv.toString('hex') +
     ':' +
     tag.toString('hex') +
     ':' +
     encrypted.toString('hex')
   );
 }
