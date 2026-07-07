import { INV_MIX_COLUMNS_MATRIX, MIX_COLUMNS_MATRIX } from "./constants.js";
import { gfMultiply } from "./gf256.js";
import { toByte } from "./utils.js";

/**
 * Input: AES state and 4x4 coefficient matrix.
 * Output: transformed state.
 * Formula: output[r][c] = XOR_i gfMultiply(matrix[r][i], state[i][c]).
 * Reference: FIPS-197 Section 5.1.3 and 5.3.3.
 * Complexity: O(4*4*4).
 */
export function multiplyColumns(state, matrix) {
  const next = Array.from({ length: 4 }, () => Array(4).fill(0));
  for (let col = 0; col < 4; col += 1) {
    for (let row = 0; row < 4; row += 1) {
      let value = 0;
      for (let i = 0; i < 4; i += 1) value ^= gfMultiply(matrix[row][i], state[i][col]);
      next[row][col] = toByte(value);
    }
  }
  return next;
}

/**
 * Input: AES state.
 * Output: state after MixColumns.
 * Formula: fixed AES matrix [02 03 01 01; ...] times each column.
 * Reference: FIPS-197 Section 5.1.3.
 * Complexity: O(64).
 */
export function mixColumns(state) {
  return multiplyColumns(state, MIX_COLUMNS_MATRIX);
}

/**
 * Input: AES state.
 * Output: state after inverse MixColumns.
 * Formula: fixed inverse AES matrix [0E 0B 0D 09; ...] times each column.
 * Reference: FIPS-197 Section 5.3.3.
 * Complexity: O(64).
 */
export function invMixColumns(state) {
  return multiplyColumns(state, INV_MIX_COLUMNS_MATRIX);
}

/**
 * Input: one 4-byte column and coefficient matrix.
 * Output: detailed GF(2^8) calculation rows for learning display.
 * Formula: each result byte is XOR of four GF products.
 * Reference: FIPS-197 Section 4.3.
 * Complexity: O(16).
 */
export function explainColumn(column, matrix = MIX_COLUMNS_MATRIX) {
  return matrix.map((row) => {
    const terms = row.map((factor, index) => ({
      factor,
      byte: column[index],
      product: gfMultiply(factor, column[index])
    }));
    const result = terms.reduce((acc, term) => acc ^ term.product, 0);
    return { terms, result: toByte(result) };
  });
}
