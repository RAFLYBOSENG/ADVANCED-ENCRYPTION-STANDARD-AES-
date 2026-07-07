import { addRoundKey } from "./addRoundKey.js";
import { expandKey } from "./keyExpansion.js";
import { bytesToState, stateToBytes, stateToHexMatrix } from "./matrix.js";
import { invMixColumns, mixColumns } from "./mixColumns.js";
import { invShiftRows, shiftRows } from "./shiftRows.js";
import { invSubBytes, subBytes } from "./subBytes.js";
import { bytesToHex } from "./utils.js";

function snapshot(title, round, operation, state, explanation, formula, input = null) {
  return {
    title,
    round,
    operation,
    explanation,
    formula,
    input,
    output: bytesToHex(stateToBytes(state)),
    state: stateToHexMatrix(state)
  };
}

/**
 * Input: 16 plaintext bytes and 16 key bytes.
 * Output: ciphertext bytes plus full learning trace.
 * Formula: AES-128 ECB single block: initial AddRoundKey, 9 full rounds, final round without MixColumns.
 * Reference: FIPS-197 Section 5.1.
 * Complexity: O(Nr * 16), Nr=10.
 */
export function encryptBlock(plainBytes, keyBytes) {
  const keySchedule = expandKey(keyBytes);
  let state = bytesToState(plainBytes);
  const steps = [snapshot("State awal plaintext", 0, "Input", state, "Plaintext disusun ke state matrix secara column-major.", "state[r][c] = input[4c+r]")];

  state = addRoundKey(state, keySchedule.roundKeys[0]);
  steps.push(snapshot("Initial Round - AddRoundKey RK0", 0, "AddRoundKey", state, "Setiap byte state di-XOR dengan RoundKey0.", "state = state XOR RoundKey0"));

  for (let round = 1; round <= 9; round += 1) {
    steps.push(snapshot(`Round ${round} - State sebelum transformasi`, round, "RoundStart", state, "Awal ronde sebelum SubBytes.", "state_in"));
    state = subBytes(state);
    steps.push(snapshot(`Round ${round} - SubBytes`, round, "SubBytes", state, "Setiap byte diganti memakai tabel S-Box AES resmi.", "S'[r][c] = SBox[S[r][c]]"));
    state = shiftRows(state);
    steps.push(snapshot(`Round ${round} - ShiftRows`, round, "ShiftRows", state, "Row 0 tidak bergeser, row 1/2/3 bergeser kiri 1/2/3 byte.", "row r: leftShift(r)"));
    state = mixColumns(state);
    steps.push(snapshot(`Round ${round} - MixColumns`, round, "MixColumns", state, "Setiap kolom dikalikan matriks tetap AES dalam GF(2^8).", "[02 03 01 01; ...] x column"));
    state = addRoundKey(state, keySchedule.roundKeys[round]);
    steps.push(snapshot(`Round ${round} - AddRoundKey RK${round}`, round, "AddRoundKey", state, "State di-XOR dengan round key ronde ini.", `state = state XOR RoundKey${round}`));
  }

  state = subBytes(state);
  steps.push(snapshot("Round 10 - SubBytes", 10, "SubBytes", state, "Final round tetap memakai S-Box.", "S'[r][c] = SBox[S[r][c]]"));
  state = shiftRows(state);
  steps.push(snapshot("Round 10 - ShiftRows", 10, "ShiftRows", state, "Final round menggeser baris seperti ronde biasa.", "row r: leftShift(r)"));
  state = addRoundKey(state, keySchedule.roundKeys[10]);
  steps.push(snapshot("Round 10 - AddRoundKey RK10", 10, "AddRoundKey", state, "Final round tidak memakai MixColumns.", "state = state XOR RoundKey10"));

  return { cipherBytes: stateToBytes(state), steps, keySchedule };
}

/**
 * Input: 16 ciphertext bytes and 16 key bytes.
 * Output: plaintext bytes plus full inverse learning trace.
 * Formula: AES-128 inverse cipher with round keys applied from RK10 to RK0.
 * Reference: FIPS-197 Section 5.3.
 * Complexity: O(Nr * 16), Nr=10.
 */
export function decryptBlock(cipherBytes, keyBytes) {
  const keySchedule = expandKey(keyBytes);
  let state = bytesToState(cipherBytes);
  const steps = [snapshot("State awal ciphertext", 10, "Input", state, "Ciphertext disusun ke state matrix secara column-major.", "state[r][c] = input[4c+r]")];

  state = addRoundKey(state, keySchedule.roundKeys[10]);
  steps.push(snapshot("Initial Inverse - AddRoundKey RK10", 10, "AddRoundKey", state, "Dekripsi dimulai dengan RoundKey10.", "state = state XOR RoundKey10"));

  for (let round = 9; round >= 1; round -= 1) {
    state = invShiftRows(state);
    steps.push(snapshot(`Inverse Round ${round} - InvShiftRows`, round, "InvShiftRows", state, "Row 1/2/3 bergeser kanan 1/2/3 byte.", "row r: rightShift(r)"));
    state = invSubBytes(state);
    steps.push(snapshot(`Inverse Round ${round} - InvSubBytes`, round, "InvSubBytes", state, "Setiap byte diganti memakai inverse S-Box.", "S'[r][c] = InvSBox[S[r][c]]"));
    state = addRoundKey(state, keySchedule.roundKeys[round]);
    steps.push(snapshot(`Inverse Round ${round} - AddRoundKey RK${round}`, round, "AddRoundKey", state, "State di-XOR dengan round key yang sama dari enkripsi.", `state = state XOR RoundKey${round}`));
    state = invMixColumns(state);
    steps.push(snapshot(`Inverse Round ${round} - InvMixColumns`, round, "InvMixColumns", state, "Kolom dikalikan matriks inverse MixColumns dalam GF(2^8).", "[0E 0B 0D 09; ...] x column"));
  }

  state = invShiftRows(state);
  steps.push(snapshot("Final Inverse - InvShiftRows", 0, "InvShiftRows", state, "Langkah inverse final sebelum inverse S-Box.", "row r: rightShift(r)"));
  state = invSubBytes(state);
  steps.push(snapshot("Final Inverse - InvSubBytes", 0, "InvSubBytes", state, "Inverse S-Box mengembalikan substitusi final.", "S'[r][c] = InvSBox[S[r][c]]"));
  state = addRoundKey(state, keySchedule.roundKeys[0]);
  steps.push(snapshot("Final Inverse - AddRoundKey RK0", 0, "AddRoundKey", state, "RoundKey0 mengembalikan plaintext.", "state = state XOR RoundKey0"));

  return { plainBytes: stateToBytes(state), steps, keySchedule };
}
