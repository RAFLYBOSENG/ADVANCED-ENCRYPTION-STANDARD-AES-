import { asciiToBytes, hexToBytes } from "./utils.js";

/**
 * Input: plaintext mode and raw value.
 * Output: exactly 16 plaintext bytes.
 * Formula: HEX parses 32 digits; ASCII encodes UTF-8 and pads with zero bytes to 16.
 * Reference: AES-128 block size is 128 bits.
 * Complexity: O(n).
 */
export function parsePlaintext(mode, value) {
  const raw = String(value ?? "");
  const bytes = mode === "hex" ? hexToBytes(raw) : asciiToBytes(raw);
  if (bytes.length > 16) throw new Error("Plaintext single block maksimal 16 byte.");
  return [...bytes, ...Array(16 - bytes.length).fill(0)];
}

/**
 * Input: ciphertext HEX.
 * Output: exactly 16 ciphertext bytes.
 * Formula: parse 32 hex digits.
 * Reference: AES-128 block size is 128 bits.
 * Complexity: O(n).
 */
export function parseCiphertext(value) {
  const bytes = hexToBytes(value);
  if (bytes.length !== 16) throw new Error("Ciphertext harus tepat 16 byte / 32 digit HEX.");
  return bytes;
}

/**
 * Input: key HEX.
 * Output: exactly 16 key bytes.
 * Formula: parse 32 hex digits.
 * Reference: AES-128 key size is 128 bits.
 * Complexity: O(n).
 */
export function parseKey(value) {
  const bytes = hexToBytes(value);
  if (bytes.length !== 16) throw new Error("Key AES-128 harus tepat 16 byte / 32 digit HEX.");
  return bytes;
}
