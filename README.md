# AES-128 Learning Simulator

Aplikasi web statis untuk simulasi AES-128 sesuai FIPS-197. Engine AES dibuat manual tanpa CryptoJS, Web Crypto API, Node crypto AES, OpenSSL AES, atau library AES lain.

## Cara Menjalankan

### Lokal

1. Pastikan Node.js tersedia.
2. Jalankan test:

```bash
npm test
```

Jika PowerShell memblokir `npm.ps1`, pakai:

```bash
cmd /c npm.cmd test
```

3. Jalankan aplikasi:

```bash
npm start
```

Jika PowerShell memblokir `npm.ps1`, pakai:

```bash
cmd /c npm.cmd start
```

4. Buka browser ke:

```text
http://localhost:5173
```

## Test Vector FIPS-197

Plaintext:

```text
00112233445566778899AABBCCDDEEFF
```

Key:

```text
000102030405060708090A0B0C0D0E0F
```

Ciphertext yang benar:

```text
69C4E0D86A7B0430D8CDB78070B4C55A
```
