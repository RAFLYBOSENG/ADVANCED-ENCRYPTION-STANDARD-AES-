/**
 * Input: number.
 * Output: byte clamped to 0..255.
 * Formula: b mod 2^8.
 * Reference: FIPS-197 byte-oriented state representation.
 * Complexity: O(1).
 */
export function toByte(value) {
  return value & 0xff;
}

/**
 * Input: byte.
 * Output: two-character uppercase hexadecimal string.
 * Formula: byte -> base16.
 * Reference: FIPS-197 examples use hexadecimal bytes.
 * Complexity: O(1).
 */
export function byteToHex(byte) {
  return toByte(byte).toString(16).padStart(2, "0").toUpperCase();
}

/**
 * Input: byte array.
 * Output: uppercase hexadecimal string.
 * Formula: concatenate byteToHex for every byte.
 * Reference: FIPS-197 Appendix C test vectors.
 * Complexity: O(n).
 */
export function bytesToHex(bytes) {
  return Array.from(bytes, byteToHex).join("");
}

/**
 * Input: hexadecimal string with optional spaces.
 * Output: array of bytes.
 * Formula: parse every two hex nibbles as one byte.
 * Reference: FIPS-197 vectors are provided as hex.
 * Complexity: O(n).
 */
export function hexToBytes(hex) {
  const clean = String(hex).replace(/\s+/g, "").toUpperCase();
  if (!/^[0-9A-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("HEX harus berisi pasangan digit 0-9 atau A-F.");
  }
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(Number.parseInt(clean.slice(i, i + 2), 16));
  }
  return bytes;
}

/**
 * Input: string.
 * Output: byte array encoded as UTF-8 and limited by caller.
 * Formula: TextEncoder(s).
 * Reference: AES operates on bytes, not characters.
 * Complexity: O(n).
 */
export function asciiToBytes(text) {
  return Array.from(new TextEncoder().encode(String(text)));
}

/**
 * Input: byte array.
 * Output: printable text if possible, otherwise escaped dot markers.
 * Formula: byte -> char for printable ASCII.
 * Reference: AES output is arbitrary bytes.
 * Complexity: O(n).
 */
export function bytesToPrintableAscii(bytes) {
  return Array.from(bytes, (byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".")).join("");
}

/**
 * Input: byte array.
 * Output: binary string grouped per byte.
 * Formula: byte -> base2 padded to eight bits.
 * Reference: AES block size is 128 bits.
 * Complexity: O(n).
 */
export function bytesToBinary(bytes) {
  return Array.from(bytes, (byte) => toByte(byte).toString(2).padStart(8, "0")).join(" ");
}
