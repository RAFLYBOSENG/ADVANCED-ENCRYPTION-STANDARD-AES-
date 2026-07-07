import { decryptBlock, encryptBlock } from "../aes/aes.js";
import { bytesToBinary, bytesToHex, bytesToPrintableAscii } from "../aes/utils.js";
import { bytesToState, stateToHexMatrix } from "../aes/matrix.js";
import { parseCiphertext, parseKey, parsePlaintext } from "../aes/validator.js";

const state = {
  activeView: "dashboard",
  mode: "encrypt",
  activeStepIndex: 0,
  timer: null,
  encryption: null,
  decryption: null
};

const theory = [
  ["Apa itu AES", "Advanced Encryption Standard adalah block cipher simetris yang bekerja pada blok 128 bit dan memakai transformasi berulang."],
  ["State Matrix", "16 byte data disusun menjadi tabel 4x4 secara column-major: state[r][c] = input[4c+r]."],
  ["Round", "AES-128 memiliki initial round, 9 full rounds, dan final round tanpa MixColumns."],
  ["SBox", "S-Box adalah lookup table non-linear resmi AES untuk operasi SubBytes."],
  ["Rcon", "Round constant dipakai pada Key Expansion setiap empat word untuk mencegah pola kunci berulang."],
  ["MixColumns", "Setiap kolom state dikalikan matriks tetap AES dalam GF(2^8)."],
  ["GF(2^8)", "Operasi byte dilakukan sebagai polinomial biner dengan reduksi 0x11B, bukan perkalian integer biasa."]
];

function $(selector) {
  return document.querySelector(selector);
}

function all(selector) {
  return Array.from(document.querySelectorAll(selector));
}

function setText(selector, value) {
  $(selector).textContent = value;
}

function markFieldStatus(input, isValid, message) {
  input.classList.toggle("valid", isValid);
  input.classList.toggle("invalid", !isValid);
  const hint = input.closest(".field-group")?.querySelector(".field-hint");
  if (hint) {
    hint.textContent = message;
    hint.classList.toggle("invalid-text", !isValid);
  }
}

function toast(message, isError = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.hidden = false;
  window.setTimeout(() => {
    box.hidden = true;
  }, 2800);
}

function renderMatrix(target, matrix) {
  const root = typeof target === "string" ? $(target) : target;
  root.replaceChildren();
  const wrapper = document.createElement("div");
  wrapper.className = "matrix";
  matrix.flat().forEach((byte) => {
    const cell = document.createElement("div");
    cell.className = "matrix-cell";
    cell.textContent = byte;
    wrapper.append(cell);
  });
  root.append(wrapper);
}

function selectView(view) {
  state.activeView = view;
  all(".view").forEach((node) => node.classList.toggle("active", node.id === view));
  all(".nav-item").forEach((node) => node.classList.toggle("active", node.dataset.view === view));
  const label = view.split("-").map((word) => word[0].toUpperCase() + word.slice(1)).join(" ");
  setText("#breadcrumb", `${label} / AES-128`);
  setText("#viewTitle", label === "Dashboard" ? "Simulasi Advanced Encryption Standard" : label);
}

function runEncrypt() {
  const plainBytes = parsePlaintext($("#plainMode").value, $("#plaintext").value);
  const keyBytes = parseKey($("#keyInput").value);
  state.encryption = encryptBlock(plainBytes, keyBytes);
  state.mode = "encrypt";
  state.activeStepIndex = 0;
  const cipher = state.encryption.cipherBytes;
  $("#cipherInput").value = bytesToHex(cipher);
  setText("#cipherHex", bytesToHex(cipher));
  setText("#cipherBinary", bytesToBinary(cipher));
  setText("#cipherAscii", bytesToPrintableAscii(cipher));
  renderMatrix("#cipherMatrix", stateToHexMatrix(bytesToState(cipher)));
  renderInitialKeyState(keyBytes);
  renderKeyExpansion();
  renderSteps();
  //renderTesting();
  renderMatrix("#heroMatrix", state.encryption.steps.at(-1).state);
  setText("#validationStatus", "Encryption ready");
}

function runDecrypt() {
  const cipherBytes = parseCiphertext($("#cipherInput").value);
  const keyBytes = parseKey($("#keyInput").value);
  state.decryption = decryptBlock(cipherBytes, keyBytes);
  state.mode = "decrypt";
  state.activeStepIndex = 0;
  const plain = state.decryption.plainBytes;
  setText("#plainHex", bytesToHex(plain));
  setText("#plainAscii", bytesToPrintableAscii(plain));
  renderMatrix("#plainMatrix", stateToHexMatrix(bytesToState(plain)));
  renderInitialKeyState(keyBytes);
  renderKeyExpansion();
  renderSteps();
  setText("#validationStatus", "Decryption ready");
}

function safeRun(action) {
  try {
    action();
    toast("Proses AES berhasil dihitung.");
  } catch (error) {
    toast(error.message, true);
    setText("#validationStatus", "Input error");
  }
}

function validatePlaintextField() {
  const mode = $("#plainMode").value;
  const input = $("#plaintext");
  const value = input.value;
  if (mode === "hex") {
    const clean = value.replace(/\s+/g, "");
    const isHex = /^[0-9A-Fa-f]*$/.test(clean);
    const validLength = clean.length <= 32 && clean.length % 2 === 0;
    const message = !isHex
      ? "Plaintext HEX hanya boleh berisi digit 0-9 dan A-F."
      : clean.length > 32
      ? "Plaintext HEX maksimal 32 karakter."
      : clean.length % 2 !== 0
      ? "Plaintext HEX harus genap jumlah digit."
      : "Plaintext HEX valid untuk satu blok AES-128.";
    markFieldStatus(input, isHex && validLength, message);
    return isHex && validLength;
  }
  const validAscii = value.length <= 16;
  const message = validAscii
    ? "Plaintext ASCII valid untuk satu blok AES-128."
    : "Plaintext ASCII maksimal 16 karakter.";
  markFieldStatus(input, validAscii, message);
  return validAscii;
}

function validateHexField(input, label) {
  const value = input.value.replace(/\s+/g, "");
  const isHex = /^[0-9A-Fa-f]*$/.test(value);
  const validLength = value.length === 32;
  const message = !isHex
    ? `${label} harus berisi digit HEX 0-9 dan A-F.`
    : !validLength
    ? `${label} harus tepat 32 karakter HEX.`
    : `${label} valid untuk AES-128.`;
  markFieldStatus(input, isHex && validLength, message);
  return isHex && validLength;
}

function validateCiphertextField() {
  return validateHexField($("#cipherInput"), "Ciphertext");
}

function validateKeyField() {
  return validateHexField($("#keyInput"), "Key");
}

function validateInputs() {
  const validPlain = validatePlaintextField();
  const validKey = validateKeyField();
  const validCipher = validateCiphertextField();
  return validPlain && validKey && validCipher;
}

function activeTrace() {
  return state.mode === "decrypt" ? state.decryption?.steps ?? [] : state.encryption?.steps ?? [];
}

function renderActiveStep() {
  const steps = activeTrace();
  const step = steps[state.activeStepIndex] ?? steps[0];
  const root = $("#activeStep");
  root.replaceChildren();
  if (!step) return;

  const grid = document.createElement("div");
  grid.className = "active-step-grid";
  const text = document.createElement("div");
  const title = document.createElement("h2");
  title.textContent = step.title;
  const desc = document.createElement("p");
  desc.textContent = step.explanation;
  const formula = document.createElement("code");
  formula.className = "formula";
  formula.textContent = step.formula;
  text.append(title, desc, formula);
  const matrix = document.createElement("div");
  renderMatrix(matrix, step.state);
  grid.append(text, matrix);
  root.append(grid);
}

function renderSteps() {
  const list = $("#stepList");
  const query = $("#stepSearch").value.trim().toLowerCase();
  const steps = activeTrace();
  list.replaceChildren();
  renderActiveStep();
  steps
    .map((step, index) => ({ step, index }))
    .filter(({ step }) => `${step.title} ${step.operation} ${step.explanation}`.toLowerCase().includes(query))
    .forEach(({ step, index }) => {
      const details = document.createElement("details");
      details.className = "step-card";
      details.open = index === state.activeStepIndex;
      const summary = document.createElement("summary");
      summary.textContent = `${index + 1}. ${step.title}`;
      const desc = document.createElement("p");
      desc.textContent = step.explanation;
      const formula = document.createElement("code");
      formula.className = "formula";
      formula.textContent = step.formula;
      const matrix = document.createElement("div");
      renderMatrix(matrix, step.state);
      details.addEventListener("toggle", () => {
        if (details.open) {
          state.activeStepIndex = index;
          renderActiveStep();
        }
      });
      details.append(summary, desc, formula, matrix);
      list.append(details);
    });
}

function renderInitialKeyState(keyBytes) {
  if (!keyBytes) return;
  renderMatrix("#initialKeyState", stateToHexMatrix(bytesToState(keyBytes)));
}

function renderRoundKeyCard(roundKey, label) {
  const card = document.createElement("article");
  card.className = "round-key";
  const title = document.createElement("strong");
  title.textContent = label;
  card.append(title);
  const matrix = document.createElement("div");
  renderMatrix(matrix, stateToHexMatrix(bytesToState(roundKey)));
  card.append(matrix);
  return card;
}

function renderKeyScheduleDetails(schedule) {
  const container = $("#keyScheduleDetails");
  container.replaceChildren();
  if (!schedule) return;
  schedule.steps
    .filter((step) => Boolean(step.rotWord))
    .forEach((step) => {
      const item = document.createElement("div");
      item.className = "key-schedule-step";
      const title = document.createElement("strong");
      title.textContent = `W${step.index} = g(W${step.index - 1}) XOR W${step.index - 4}`;
      const body = document.createElement("div");
      body.className = "key-schedule-step-body";
      body.innerHTML = `
        <p><strong>RotWord:</strong> ${step.rotWord.map((b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase()}</p>
        <p><strong>SubWord:</strong> ${step.subWord.map((b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase()}</p>
        <p><strong>Rcon:</strong> ${step.rcon.map((b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase()}</p>
        <p><strong>Result:</strong> ${step.result.map((b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase()}</p>
      `;
      item.append(title, body);
      container.append(item);
    });
}

function resetInputs() {
  $("#plaintext").value = "";
  $("#plainMode").value = "hex";
  $("#cipherInput").value = "";
  $("#keyInput").value = "";
  $("#stepSearch").value = "";
  $("#wordSearch").value = "";
  setText("#cipherHex", "");
  setText("#cipherBinary", "");
  setText("#cipherAscii", "");
  setText("#plainHex", "");
  setText("#plainAscii", "");
  $("#cipherMatrix").replaceChildren();
  $("#plainMatrix").replaceChildren();
  $("#heroMatrix").replaceChildren();
  $("#stepList").replaceChildren();
  $("#activeStep").replaceChildren();
  $("#roundKeys").replaceChildren();
  $("#words").replaceChildren();
  $("#initialKeyState").replaceChildren();
  $("#keyScheduleDetails").replaceChildren();
  setText("#validationStatus", "Ready");
  state.encryption = null;
  state.decryption = null;
  state.mode = "encrypt";
  state.activeStepIndex = 0;
}

function togglePlay() {
  if (state.timer) {
    window.clearInterval(state.timer);
    state.timer = null;
    $("#playSteps").textContent = "Play";
    return;
  }
  $("#playSteps").textContent = "Pause";
  state.timer = window.setInterval(() => {
    const steps = activeTrace();
    if (state.activeStepIndex >= steps.length - 1) {
      togglePlay();
      return;
    }
    moveStep(1);
  }, 900);
}

function renderKeyExpansion() {
  const schedule = state.encryption?.keySchedule || state.decryption?.keySchedule;
  if (!schedule) return;
  const wordQuery = $("#wordSearch").value.trim().toLowerCase();
  const roundKeys = $("#roundKeys");
  const words = $("#words");
  roundKeys.replaceChildren();
  words.replaceChildren();
  renderKeyScheduleDetails(schedule);
  schedule.roundKeys.forEach((roundKey, index) => {
    const label = `RoundKey${index}`;
    const text = `${label} ${bytesToHex(roundKey)}`.toLowerCase();
    if (!wordQuery || text.includes(wordQuery)) {
      roundKeys.append(renderRoundKeyCard(roundKey, label));
    }
  });
  schedule.wordLabels
    .filter((item) => `${item.label} ${item.hex}`.toLowerCase().includes(wordQuery))
    .forEach((item) => {
      const card = document.createElement("article");
      card.className = "word-card";
      const title = document.createElement("strong");
      title.textContent = item.label;
      const code = document.createElement("code");
      code.textContent = item.hex;
      card.append(title, code);
      words.append(card);
    });
}

function renderTheory() {
  const root = $("#theoryGrid");
  root.replaceChildren();
  theory.forEach(([titleText, body]) => {
    const card = document.createElement("article");
    card.className = "theory-card";
    const title = document.createElement("h2");
    title.textContent = titleText;
    const text = document.createElement("p");
    text.textContent = body;
    const detail = document.createElement("span");
    detail.textContent = "Lihat Detail: konsep ini dipakai langsung di trace ronde dan key expansion.";
    card.append(title, text, detail);
    root.append(card);
  });
}

/*function renderTesting() {
  const expected = "";
  const actual = state.encryption ? bytesToHex(state.encryption.cipherBytes) : "";
  const result = $("#testResult");
  result.className = `test-result ${actual === expected ? "pass" : "fail"}`;
  result.textContent = actual === expected ? `PASS: ${actual}` : `FAIL: hasil ${actual || "-"} tidak sama dengan ${expected}`;
}*/

function copyFrom(id) {
  const value = $(`#${id}`).textContent;
  navigator.clipboard.writeText(value).then(() => toast("Berhasil disalin."));
}

function downloadResult() {
  const payload = [
    "AES-128 Learning Simulator Result",
    `Ciphertext HEX: ${$("#cipherHex").textContent}`,
    `Ciphertext Binary: ${$("#cipherBinary").textContent}`,
    `Ciphertext ASCII: ${$("#cipherAscii").textContent}`
  ].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([payload], { type: "text/plain" }));
  link.download = "aes-result.txt";
  link.click();
  URL.revokeObjectURL(link.href);
}

function bindEvents() {
  all(".nav-item").forEach((button) => button.addEventListener("click", () => selectView(button.dataset.view)));
  $("#themeToggle").addEventListener("click", () => {
    document.body.classList.toggle("light");
    $("#themeToggle").textContent = document.body.classList.contains("light") ? "Dark Mode" : "Light Mode";
  });
  $("#runEncrypt").addEventListener("click", () => safeRun(runEncrypt));
  $("#runDecrypt").addEventListener("click", () => safeRun(runDecrypt));
  $("#resetInputs").addEventListener("click", resetInputs);
  $("#plaintext").addEventListener("input", validatePlaintextField);
  $("#cipherInput").addEventListener("input", validateCiphertextField);
  $("#keyInput").addEventListener("input", validateKeyField);
  $("#plainMode").addEventListener("change", () => {
    applyPlaintextConstraints();
    validatePlaintextField();
  });
  $("#prevStep").addEventListener("click", () => moveStep(-1));
  $("#nextStep").addEventListener("click", () => moveStep(1));
  $("#playSteps").addEventListener("click", togglePlay);
  $("#expandAll").addEventListener("click", () => all(".step-card").forEach((node) => (node.open = true)));
  $("#collapseAll").addEventListener("click", () => all(".step-card").forEach((node) => (node.open = false)));
  $("#stepSearch").addEventListener("input", renderSteps);
  $("#plainMode").addEventListener("change", applyPlaintextConstraints);
  $("#wordSearch").addEventListener("input", renderKeyExpansion);
  $("#downloadResult").addEventListener("click", downloadResult);
  all("[data-copy]").forEach((button) => button.addEventListener("click", () => copyFrom(button.dataset.copy)));
}

function applyPlaintextConstraints() {
  const mode = $("#plainMode").value;
  const input = $("#plaintext");
  if (!input) return;
  if (mode === "hex") {
    input.maxLength = 32;
    input.placeholder = "Max 32 HEX";
  } else {
    input.maxLength = 16;
    input.placeholder = "Max 16 ASCII";
  }
  if (input.value.length > input.maxLength) {
    input.value = input.value.slice(0, input.maxLength);
  }
}

bindEvents();
applyPlaintextConstraints();
renderTheory();
safeRun(runEncrypt);
safeRun(runDecrypt);
selectView("dashboard");
