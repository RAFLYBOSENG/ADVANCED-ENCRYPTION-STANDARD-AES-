/**
 * Input: AES state.
 * Output: state with rows shifted left by row index.
 * Formula: row r becomes row[r][(c+r) mod 4].
 * Reference: FIPS-197 Section 5.1.2.
 * Complexity: O(16).
 */
export function shiftRows(state) {
  return state.map((row, rowIndex) => row.map((_, col) => row[(col + rowIndex) % 4]));
}

/**
 * Input: AES state.
 * Output: state with rows shifted right by row index.
 * Formula: row r becomes row[r][(c-r+4) mod 4].
 * Reference: FIPS-197 Section 5.3.1.
 * Complexity: O(16).
 */
export function invShiftRows(state) {
  return state.map((row, rowIndex) => row.map((_, col) => row[(col - rowIndex + 4) % 4]));
}
