import { RCON, S_BOX } from "./constants.js";
import { byteToHex, bytesToHex, toByte } from "./utils.js";

/**
 * Input: 4-byte word.
 * Output: word rotated left by one byte.
 * Formula: [b1,b2,b3,b0].
 * Reference: FIPS-197 Section 5.2 RotWord.
 * Complexity: O(1).
 */
export function rotWord(word) {
  return [word[1], word[2], word[3], word[0]];
}

/**
 * Input: 4-byte word.
 * Output: word substituted through AES S-Box.
 * Formula: SubWord([b0..b3]) = [SBox[b0]..SBox[b3]].
 * Reference: FIPS-197 Section 5.2 SubWord.
 * Complexity: O(4).
 */
export function subWord(word) {
  return word.map((byte) => S_BOX[byte]);
}

/**
 * Input: two equal-length byte arrays.
 * Output: XORed byte array.
 * Formula: out[i] = a[i] XOR b[i].
 * Reference: FIPS-197 AddRoundKey and key schedule XOR.
 * Complexity: O(n).
 */
export function xorWords(a, b) {
  return a.map((byte, index) => toByte(byte ^ b[index]));
}

/**
 * Input: 16-byte AES-128 key.
 * Output: W0..W43, RoundKey0..RoundKey10, and learning trace.
 * Formula: W[i]=W[i-4] XOR temp, with RotWord/SubWord/Rcon every Nk words.
 * Reference: FIPS-197 Section 5.2, Nk=4, Nb=4, Nr=10.
 * Complexity: O(44).
 */
export function expandKey(keyBytes) {
  if (keyBytes.length !== 16) throw new Error("Key AES-128 harus tepat 16 byte / 32 digit HEX.");
  const words = [];
  const steps = [];
  for (let i = 0; i < 4; i += 1) words.push(keyBytes.slice(i * 4, i * 4 + 4));
  for (let i = 4; i < 44; i += 1) {
    const originalTemp = words[i - 1].slice();
    let temp = originalTemp.slice();
    let rot = null;
    let sub = null;
    let rcon = null;
    if (i % 4 === 0) {
      rot = rotWord(temp);
      sub = subWord(rot);
      rcon = RCON[i / 4];
      temp = xorWords(sub, rcon);
    }
    const word = xorWords(words[i - 4], temp);
    words.push(word);
    steps.push({
      index: i,
      previous: originalTemp,
      rotWord: rot,
      subWord: sub,
      rcon,
      source: words[i - 4],
      result: word,
      formula: `W${i} = W${i - 4} XOR ${i % 4 === 0 ? "SubWord(RotWord(W" + (i - 1) + ")) XOR Rcon" : "W" + (i - 1)}`
    });
  }
  const roundKeys = Array.from({ length: 11 }, (_, round) => words.slice(round * 4, round * 4 + 4).flat());
  return {
    words,
    roundKeys,
    steps,
    wordLabels: words.map((word, index) => ({ label: `W${index}`, hex: word.map(byteToHex).join(" ") })),
    roundKeyLabels: roundKeys.map((roundKey, index) => ({ label: `RoundKey${index}`, hex: bytesToHex(roundKey) }))
  };
}
