import { byteToHex } from "./utils.js";

/**
 * Input: 16 bytes.
 * Output: AES state as state[row][column].
 * Formula: state[r][c] = input[4c+r].
 * Reference: FIPS-197 Section 3.4 column-major state.
 * Complexity: O(16).
 */
export function bytesToState(bytes) {
  if (bytes.length !== 16) throw new Error("AES-128 single block membutuhkan tepat 16 byte.");
  return Array.from({ length: 4 }, (_, row) => Array.from({ length: 4 }, (_, col) => bytes[col * 4 + row]));
}

/**
 * Input: AES state.
 * Output: 16 bytes in column-major order.
 * Formula: output[4c+r] = state[r][c].
 * Reference: FIPS-197 Section 3.4.
 * Complexity: O(16).
 */
export function stateToBytes(state) {
  const bytes = [];
  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) bytes.push(state[row][col]);
  }
  return bytes;
}

/**
 * Input: AES state.
 * Output: deep-copied AES state.
 * Formula: copy each row and byte.
 * Reference: FIPS-197 transformations produce new state values.
 * Complexity: O(16).
 */
export function cloneState(state) {
  return state.map((row) => row.slice());
}

/**
 * Input: 16-byte round key.
 * Output: AES state-shaped key.
 * Formula: bytesToState(roundKey).
 * Reference: AddRoundKey aligns round key bytes with state columns.
 * Complexity: O(16).
 */
export function roundKeyToState(roundKey) {
  return bytesToState(roundKey);
}

/**
 * Input: AES state.
 * Output: 4x4 uppercase hex matrix for display.
 * Formula: byteToHex for every cell.
 * Reference: FIPS-197 displays state bytes as hex.
 * Complexity: O(16).
 */
export function stateToHexMatrix(state) {
  return state.map((row) => row.map(byteToHex));
}
