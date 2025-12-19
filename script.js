// =============================================================================
// PARTIE 1 : INTERFACE UTILISATEUR & UTILITAIRES DE BASE (Personne 1)
// Responsable : Gestion du DOM, Lecture de fichiers, Fonctions de base (Padding, XOR...)
// =============================================================================

let encryptFile = null;
let decryptFile = null;

// --- Gestion des Onglets et UI ---

function switchTab(tab) {
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));
    if (tab === 'encrypt') {
        tabs[0].classList.add('active');
        document.getElementById('encrypt-tab').classList.add('active');
    } else {
        tabs[1].classList.add('active');
        document.getElementById('decrypt-tab').classList.add('active');
    }
    clearAlert();
}

function handleFileSelect(type) {
    const input = document.getElementById(type + '-file');
    const file = input.files[0];
    if (file) {
        if (type === 'encrypt') encryptFile = file;
        else decryptFile = file;
        document.getElementById(type + '-file-name').textContent = file.name;
        const sizeDiv = document.getElementById(type + '-file-size');
        sizeDiv.textContent = 'Taille: ' + formatFileSize(file.size);
        sizeDiv.classList.remove('hidden');
        clearAlert();
    }
}

function toggleModeSelect() {
    const modeGroup = document.getElementById('mode-group');
    modeGroup.style.display = 'block';
}

function toggleDecryptModeSelect() {
    const modeGroup = document.getElementById('decrypt-mode-group');
    modeGroup.style.display = 'block';
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function showAlert(message, type) {
    const container = document.getElementById('alert-container');
    const alertClass = type === 'error' ? 'alert-error' : 'alert-success';
    const icon = '<svg class="alert-icon" fill="currentColor" viewBox="0 0 20 20"><path d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-11a1 1 0 10-2 0v2H7a1 1 0 100 2h2v2a1 1 0 102 0v-2h2a1 1 0 100-2h-2V7z"/></svg>';
    container.innerHTML = '<div class="alert ' + alertClass + '">' + icon + '<p>' + message + '</p></div>';
}

function clearAlert() {
    const container = document.getElementById('alert-container');
    if (container) container.innerHTML = '';
}

function showSuccess(filename, size, originalSize, downloadUrl, type) {
    const container = document.getElementById('alert-container');
    const title = type === 'encrypt' ? 'Chiffrement réussi !' : 'Déchiffrement réussi !';
    const sizeInfo = originalSize ? '<p class="result-size">Taille originale: ' + formatFileSize(originalSize) + '</p>' : '';
    container.innerHTML = '<div class="alert alert-success"><div class="result-content"><p class="result-title">' + title + '</p><p class="result-text">Fichier: ' + filename + ' (' + formatFileSize(size) + ')</p>' + sizeInfo + '<a href="' + downloadUrl + '" download="' + filename + '" class="btn download-btn">Télécharger le fichier</a></div></div>';
}


// --- Utilitaires Communs ---

function pkcs7Pad(data, blockSize) {
    const padding = blockSize - (data.length % blockSize);
    const result = new Uint8Array(data.length + padding);
    result.set(data);
    for (let i = data.length; i < result.length; i++) {
        result[i] = padding;
    }
    return result;
}

function pkcs7Unpad(data) {
    if (data.length === 0) return data;
    const padding = data[data.length - 1];
    if (padding === 0 || padding > 16) return data;
    for (let i = 0; i < padding; i++) {
        if (data[data.length - 1 - i] !== padding) return data;
    }
    return data.slice(0, data.length - padding);
}

function xorBytes(a, b) {
    const len = Math.min(a.length, b.length);
    const res = new Uint8Array(len);
    for (let i = 0; i < len; i++) res[i] = a[i] ^ b[i];
    return res;
}

// =============================================================================
// PARTIE 2 : ALGORITHME DES (Data Encryption Standard) (Personne 2)
// Responsable : Tables DES, Feistel, Key Schedule DES
// =============================================================================

// Tables standard FIPS 46-3
const DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const DES_IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];

const DES_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
];
const DES_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
];

const DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// S-Box Flat (Standard 1D) 64 values per S-Box
const DES_SBOX_FLAT = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
];

async function generateDESKey(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer).slice(0, 8);
}

function bytesToBits(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let j = 7; j >= 0; j--) bits.push((bytes[i] >> j) & 1);
    }
    return bits;
}

function bitsToBytes(bits) {
    const bytes = new Uint8Array(Math.ceil(bits.length / 8));
    for (let i = 0; i < bits.length; i++) {
        if (bits[i]) bytes[Math.floor(i / 8)] |= (1 << (7 - (i % 8)));
    }
    return bytes;
}

function desPermute(input, table) {
    const output = [];
    for (let i = 0; i < table.length; i++) output.push(input[table[i] - 1]);
    return output;
}

function desLeftShift(bits, n) {
    return bits.slice(n).concat(bits.slice(0, n));
}

function bitXor(a, b) {
    const result = [];
    for (let i = 0; i < a.length; i++) result.push(a[i] ^ b[i]);
    return result;
}

function generateDESSubkeys(keyBytes) {
    const keyBits = bytesToBits(keyBytes);
    const permutedKey = desPermute(keyBits, DES_PC1);
    let C = permutedKey.slice(0, 28);
    let D = permutedKey.slice(28, 56);
    const subkeys = [];
    for (let i = 0; i < 16; i++) {
        C = desLeftShift(C, DES_SHIFTS[i]);
        D = desLeftShift(D, DES_SHIFTS[i]);
        subkeys.push(desPermute(C.concat(D), DES_PC2));
    }
    return subkeys;
}

function desSboxLookup(input) {
    const output = [];
    for (let i = 0; i < 8; i++) {
        const block = input.slice(i * 6, (i + 1) * 6);
        const row = (block[0] << 1) | block[5];
        const col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4];
        // Flat index: row * 16 + col
        const val = DES_SBOX_FLAT[i][row * 16 + col];
        for (let j = 3; j >= 0; j--) output.push((val >> j) & 1);
    }
    return output;
}

function desFFunction(right, subkey) {
    const expanded = desPermute(right, DES_E);
    const xored = bitXor(expanded, subkey);
    const sboxOutput = desSboxLookup(xored);
    return desPermute(sboxOutput, DES_P);
}

function encryptBlockDES(blockBytes, subkeys) {
    const bits = bytesToBits(blockBytes);
    const permuted = desPermute(bits, DES_IP);
    let left = permuted.slice(0, 32);
    let right = permuted.slice(32, 64);
    for (let i = 0; i < 16; i++) {
        const temp = right.slice();
        const fResult = desFFunction(right, subkeys[i]);
        right = bitXor(left, fResult);
        left = temp;
    }
    return bitsToBytes(desPermute(right.concat(left), DES_IP_INV));
}

function decryptBlockDES(blockBytes, subkeys) {
    const bits = bytesToBits(blockBytes);
    const permuted = desPermute(bits, DES_IP);
    let left = permuted.slice(0, 32);
    let right = permuted.slice(32, 64);
    const revSubkeys = subkeys.slice().reverse();
    for (let i = 0; i < 16; i++) {
        const temp = right.slice();
        const fResult = desFFunction(right, revSubkeys[i]);
        right = bitXor(left, fResult);
        left = temp;
    }
    return bitsToBytes(desPermute(right.concat(left), DES_IP_INV));
}


// =============================================================================
// PARTIE 3 : ALGORITHME AES (Advanced Encryption Standard) (Personne 3)
// Responsable : S-Box AES, ShiftRows, MixColumns, AddRoundKey, Key Exp
// =============================================================================

const AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];
const AES_INV_SBOX = new Uint8Array(256);
for (let i = 0; i < 256; i++) AES_INV_SBOX[AES_SBOX[i]] = i;
const AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

function aesMul2(x) { return (x & 0x80) ? ((x << 1) ^ 0x1b) & 0xff : (x << 1); }
function aesMul3(x) { return aesMul2(x) ^ x; }

function subBytes(state) { for (let i = 0; i < 16; i++) state[i] = AES_SBOX[state[i]]; }
function invSubBytes(state) { for (let i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]]; }

function shiftRows(s) {
    let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

function invShiftRows(s) {
    let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

function mixColumns(s) {
    for (let c = 0; c < 4; c++) {
        let idx = c * 4;
        let s0 = s[idx], s1 = s[idx + 1], s2 = s[idx + 2], s3 = s[idx + 3];
        s[idx] = aesMul2(s0) ^ aesMul3(s1) ^ s2 ^ s3;
        s[idx + 1] = s0 ^ aesMul2(s1) ^ aesMul3(s2) ^ s3;
        s[idx + 2] = s0 ^ s1 ^ aesMul2(s2) ^ aesMul3(s3);
        s[idx + 3] = aesMul3(s0) ^ s1 ^ s2 ^ aesMul2(s3);
    }
}

function aesMul(x, type) {
    let m2 = aesMul2(x); let m4 = aesMul2(m2); let m8 = aesMul2(m4);
    if (type === 9) return m8 ^ x;
    if (type === 11) return m8 ^ m2 ^ x;
    if (type === 13) return m8 ^ m4 ^ x;
    if (type === 14) return m8 ^ m4 ^ m2;
    return x;
}

function invMixColumns(s) {
    for (let c = 0; c < 4; c++) {
        let idx = c * 4;
        let s0 = s[idx], s1 = s[idx + 1], s2 = s[idx + 2], s3 = s[idx + 3];
        s[idx] = aesMul(s0, 14) ^ aesMul(s1, 11) ^ aesMul(s2, 13) ^ aesMul(s3, 9);
        s[idx + 1] = aesMul(s0, 9) ^ aesMul(s1, 14) ^ aesMul(s2, 11) ^ aesMul(s3, 13);
        s[idx + 2] = aesMul(s0, 13) ^ aesMul(s1, 9) ^ aesMul(s2, 14) ^ aesMul(s3, 11);
        s[idx + 3] = aesMul(s0, 11) ^ aesMul(s1, 13) ^ aesMul(s2, 9) ^ aesMul(s3, 14);
    }
}

function addRoundKey(state, roundKey) { for (let i = 0; i < 16; i++) state[i] ^= roundKey[i]; }

async function generateAESKey(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer).slice(0, 16);
}

function aesKeyExpansion(key) {
    const w = new Uint8Array(176);
    let temp = new Uint8Array(4);
    for (let i = 0; i < 16; i++) w[i] = key[i];
    let i = 16, rconIdx = 1;
    while (i < 176) {
        temp.set(w.slice(i - 4, i));
        if (i % 16 === 0) {
            const t = temp[0]; temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (let k = 0; k < 4; k++) temp[k] = AES_SBOX[temp[k]];
            temp[0] ^= AES_RCON[rconIdx++];
        }
        for (let k = 0; k < 4; k++) w[i + k] = w[i - 16 + k] ^ temp[k];
        i += 4;
    }
    return w;
}

function encryptBlockAES(input, expandedKey) {
    let state = new Uint8Array(input);
    addRoundKey(state, expandedKey.slice(0, 16));
    for (let round = 1; round <= 9; round++) {
        subBytes(state); shiftRows(state); mixColumns(state);
        addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
    }
    subBytes(state); shiftRows(state); addRoundKey(state, expandedKey.slice(160, 176));
    return state;
}

function decryptBlockAES(input, key) {
    let expandedKey = aesKeyExpansion(key);
    let state = new Uint8Array(input);
    addRoundKey(state, expandedKey.slice(160, 176));
    for (let round = 9; round >= 1; round--) {
        invShiftRows(state); invSubBytes(state);
        addRoundKey(state, expandedKey.slice(round * 16, (round + 1) * 16));
        invMixColumns(state);
    }
    invShiftRows(state); invSubBytes(state); addRoundKey(state, expandedKey.slice(0, 16));
    return state;
}

// =============================================================================
// PARTIE 4 : INTEGRATION, MODES OPÉRATOIRES & HANDLERS (Personne 4)
// Responsable : ECB/CBC/CFB génériques, Orchestration, Event Listeners
// =============================================================================

async function processData(data, password, algo, mode, isEncrypt) {
    let blockSize, encryptFunc, decryptFunc, keyBytes;

    if (algo === 'AES') {
        blockSize = 16;
        keyBytes = await generateAESKey(password);
        if (isEncrypt) {
            const expKey = aesKeyExpansion(keyBytes);
            encryptFunc = (b) => encryptBlockAES(b, expKey);
        } else {
            decryptFunc = (b) => decryptBlockAES(b, keyBytes);
            const expKey = aesKeyExpansion(keyBytes);
            encryptFunc = (b) => encryptBlockAES(b, expKey);
        }
    } else { // DES
        blockSize = 8;
        keyBytes = await generateDESKey(password);
        const subkeys = generateDESSubkeys(keyBytes);
        encryptFunc = (b) => encryptBlockDES(b, subkeys);
        decryptFunc = (b) => decryptBlockDES(b, subkeys);
    }

    if (isEncrypt) {
        const padded = pkcs7Pad(data, blockSize);
        const result = new Uint8Array(padded.length);
        let iv = new Uint8Array(blockSize);
        if (mode !== 'ECB') crypto.getRandomValues(iv);
        let previousBlock = new Uint8Array(iv);

        for (let i = 0; i < padded.length; i += blockSize) {
            const chunk = padded.slice(i, i + blockSize);
            let encryptedBlock;
            if (mode === 'ECB') {
                encryptedBlock = encryptFunc(chunk);
            } else if (mode === 'CBC') {
                const xored = xorBytes(chunk, previousBlock);
                encryptedBlock = encryptFunc(xored);
                previousBlock = encryptedBlock;
            } else if (mode === 'CFB') {
                const keystream = encryptFunc(previousBlock);
                encryptedBlock = xorBytes(chunk, keystream);
                previousBlock = encryptedBlock;
            }
            result.set(encryptedBlock, i);
        }
        const finalOutput = new Uint8Array(blockSize + result.length);
        finalOutput.set(iv, 0);
        finalOutput.set(result, blockSize);
        return finalOutput;
    } else {
        if (data.length < blockSize) throw new Error("Fichier invalide");
        const iv = data.slice(0, blockSize);
        const ciphertext = data.slice(blockSize);
        const result = new Uint8Array(ciphertext.length);

        let previousBlock = new Uint8Array(iv);

        for (let i = 0; i < ciphertext.length; i += blockSize) {
            const chunk = ciphertext.slice(i, i + blockSize);
            let decryptedBlock;
            if (mode === 'ECB') {
                decryptedBlock = decryptFunc(chunk);
            } else if (mode === 'CBC') {
                const decryptedRaw = decryptFunc(chunk);
                decryptedBlock = xorBytes(decryptedRaw, previousBlock);
                previousBlock = chunk;
            } else if (mode === 'CFB') {
                const keystream = encryptFunc(previousBlock);
                decryptedBlock = xorBytes(chunk, keystream);
                previousBlock = chunk;
            }
            result.set(decryptedBlock, i);
        }
        return pkcs7Unpad(result);
    }
}

async function handleEncrypt() {
    if (!encryptFile) { showAlert('Veuillez sélectionner un fichier', 'error'); return; }
    const password = document.getElementById('encrypt-password').value;
    if (!password || password.length < 4) { showAlert('Mot de passe trop court', 'error'); return; }
    const algo = document.getElementById('algorithm-select').value;
    const mode = document.getElementById('mode-select').value;
    const btn = document.getElementById('encrypt-btn');
    btn.disabled = true;
    btn.innerHTML = 'Traitement...';
    setTimeout(async () => {
        try {
            const buffer = await encryptFile.arrayBuffer();
            const data = new Uint8Array(buffer);
            const encrypted = await processData(data, password, algo, mode, true);
            const blob = new Blob([encrypted], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            showSuccess(encryptFile.name + '.enc', encrypted.length, data.length, url, 'encrypt');
        } catch (e) {
            console.error(e);
            showAlert('Erreur: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '🔒 Chiffrer le fichier';
        }
    }, 50);
}

async function handleDecrypt() {
    if (!decryptFile) { showAlert('Veuillez sélectionner un fichier', 'error'); return; }
    const password = document.getElementById('decrypt-password').value;
    if (!password) { showAlert('Mot de passe requis', 'error'); return; }
    const algo = document.getElementById('decrypt-algorithm-select').value;
    const mode = document.getElementById('decrypt-mode-select').value;
    const btn = document.getElementById('decrypt-btn');
    btn.disabled = true;
    btn.innerHTML = 'Traitement...';
    setTimeout(async () => {
        try {
            const buffer = await decryptFile.arrayBuffer();
            const data = new Uint8Array(buffer);
            const decrypted = await processData(data, password, algo, mode, false);
            let filename = decryptFile.name.replace('.enc', '') || 'decrypted_file';
            const blob = new Blob([decrypted], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            showSuccess(filename, decrypted.length, null, url, 'decrypt');
        } catch (e) {
            console.error(e);
            showAlert('Erreur (Mauvais MDP ou fichier corrompu): ' + e.message, 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '🔓 Déchiffrer le fichier';
        }
    }, 50);
}


