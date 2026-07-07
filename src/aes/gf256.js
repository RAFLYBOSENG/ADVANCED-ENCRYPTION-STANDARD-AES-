import { toByte } from "./utils.js";

/**
 * Input: two bytes.
 * Output: byte result of addition in GF(2^8).
 * Formula: a + b = a XOR b.
 * Reference: FIPS-197 Section 4.1.
 * Complexity: O(1).
 */
export function gfAdd(a, b) {
  return toByte(a ^ b);
}

/**
 * Input: one byte.
 * Output: byte multiplied by x in GF(2^8).
 * Formula: (b << 1) XOR 0x1B when the high bit overflows, reducing by x^8+x^4+x^3+x+1.
 * Reference: FIPS-197 Section 4.2.1, polynomial m(x)=x^8+x^4+x^3+x+1 (0x11B).
 * Complexity: O(1).
 */
export function xtime(byte) {
  const shifted = byte << 1;
  return toByte((byte & 0x80) !== 0 ? shifted ^ 0x1b : shifted);
}

/**
 * Input: two bytes.
 * Output: product in GF(2^8).
 * Formula: Russian-peasant multiplication using xtime and XOR addition.
 * Reference: FIPS-197 Section 4.2.1.
 * Complexity: O(8).
 */
export function gfMultiply(a, b) {
  let left = toByte(a);
  let right = toByte(b);
  let product = 0;
  for (let i = 0; i < 8; i += 1) {
    if ((right & 1) !== 0) product ^= left;
    left = xtime(left);
    right >>= 1;
  }
  return toByte(product);
}
