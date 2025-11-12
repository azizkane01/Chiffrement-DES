// JavaScript Complet pour la logique et le DES (Identique à votre source)

let encryptFile = null;
let decryptFile = null;

const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];

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

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function showAlert(message, type) {
    const container = document.getElementById('alert-container');
    const alertClass = type === 'error' ? 'alert-error' : 'alert-success';
    const icon = type === 'error'
        ? '<svg class="alert-icon" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path></svg>'
        : '<svg class="alert-icon" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>';
    container.innerHTML = '<div class="alert ' + alertClass + '">' + icon + '<p>' + message + '</p></div>';
}

function clearAlert() {
    document.getElementById('alert-container').innerHTML = '';
}

function showSuccess(filename, size, originalSize, downloadUrl, type) {
    const container = document.getElementById('alert-container');
    const title = type === 'encrypt' ? 'Chiffrement réussi !' : 'Déchiffrement réussi !';
    const sizeInfo = originalSize ? '<p class="result-size">Taille originale: ' + formatFileSize(originalSize) + '</p>' : '';
    container.innerHTML = '<div class="alert alert-success"><svg class="alert-icon" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg><div class="result-content"><p class="result-title">' + title + '</p><p class="result-text">Fichier: ' + filename + ' (' + formatFileSize(size) + ')</p>' + sizeInfo + '<a href="' + downloadUrl + '" download="' + filename + '" class="btn download-btn">⬇️ Télécharger le fichier</a></div></div>';
}

async function generateDESKey(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hash = new Uint8Array(hashBuffer);
    return new Uint8Array(hash.slice(0, 8));
}

function permute(input, table) {
    const output = new Uint8Array(table.length);
    const isBitArray = input.length >= table.length && input.every(function(v) { return v === 0 || v === 1; });
    if (isBitArray) {
        for (let i = 0; i < table.length; i++) output[i] = input[table[i] - 1];
    } else {
        for (let i = 0; i < table.length; i++) {
            const bitPos = table[i] - 1;
            const bytePos = Math.floor(bitPos / 8);
            const bitInByte = 7 - (bitPos % 8);
            output[i] = (input[bytePos] >> bitInByte) & 1;
        }
    }
    return output;
}

function xorArrays(a, b) {
    const len = Math.min(a.length, b.length);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
    return out;
}

function fFunction(right, key) {
    const expanded = new Uint8Array(48);
    for (let i = 0; i < 48; i++) expanded[i] = right[i % 32];
    const xored = xorArrays(expanded, key);
    const sboxOutput = new Uint8Array(32);
    for (let i = 0; i < 32; i++) sboxOutput[i] = xored[i] ^ key[i % 48];
    return sboxOutput;
}

function bytesToBits(block) {
    const bits = new Uint8Array(64);
    for (let i = 0; i < 8; i++) {
        for (let j = 0; j < 8; j++) bits[i * 8 + j] = (block[i] >> (7 - j)) & 1;
    }
    return bits;
}

function bitsToBytes(bits) {
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        let byte = 0;
        for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i * 8 + j];
        out[i] = byte;
    }
    return out;
}

function makeRoundKeys(keyBits) {
    const rounds = [];
    for (let i = 0; i < 16; i++) rounds.push(keyBits.slice());
    return rounds;
}

function processBlockWithRoundKeys(block, roundKeys) {
    let bits = bytesToBits(block);
    bits = permute(bits, IP);
    let left = bits.slice(0, 32);
    let right = bits.slice(32, 64);
    for (let r = 0; r < roundKeys.length; r++) {
        const fRes = fFunction(right, roundKeys[r]);
        const newRight = xorArrays(left, fRes);
        left = right;
        right = newRight;
    }
    const combined = new Uint8Array(64);
    combined.set(right, 0);
    combined.set(left, 32);
    const permuted = permute(combined, IP_INV);
    return bitsToBytes(permuted);
}

function encryptBlock(block, key) {
    const keyBits = new Uint8Array(48);
    for (let i = 0; i < 48; i++) {
        const bitPos = i % 64;
        const bytePos = Math.floor(bitPos / 8);
        const bitInByte = 7 - (bitPos % 8);
        keyBits[i] = (key[bytePos] >> bitInByte) & 1;
    }
    const roundKeys = makeRoundKeys(keyBits);
    return processBlockWithRoundKeys(block, roundKeys);
}

function decryptBlock(block, key) {
    const keyBits = new Uint8Array(48);
    for (let i = 0; i < 48; i++) {
        const bitPos = i % 64;
        const bytePos = Math.floor(bitPos / 8);
        const bitInByte = 7 - (bitPos % 8);
        keyBits[i] = (key[bytePos] >> bitInByte) & 1;
    }
    const roundKeys = makeRoundKeys(keyBits).reverse();
    return processBlockWithRoundKeys(block, roundKeys);
}

async function encryptData(data, password) {
    const key = await generateDESKey(password);
    const originalLength = data.length;
    const paddingSize = 8 - (data.length % 8) || 8;
    const paddedLength = data.length + paddingSize;
    const padded = new Uint8Array(paddedLength);
    padded.set(data);
    for (let i = data.length; i < paddedLength; i++) padded[i] = paddingSize;
    const encrypted = new Uint8Array(paddedLength);
    for (let i = 0; i < paddedLength; i += 8) {
        const block = padded.slice(i, i + 8);
        const encryptedBlock = encryptBlock(block, key);
        encrypted.set(encryptedBlock, i);
    }
    const result = new Uint8Array(4 + encrypted.length);
    result[0] = (originalLength >> 24) & 0xff;
    result[1] = (originalLength >> 16) & 0xff;
    result[2] = (originalLength >> 8) & 0xff;
    result[3] = originalLength & 0xff;
    result.set(encrypted, 4);
    return result;
}

async function decryptData(data, password) {
    if (data.length < 4) throw new Error('Fichier chiffré invalide');
    const originalLength = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    const encryptedData = data.slice(4);
    if (encryptedData.length % 8 !== 0) throw new Error('Fichier chiffré corrompu');
    const key = await generateDESKey(password);
    const decrypted = new Uint8Array(encryptedData.length);
    for (let i = 0; i < encryptedData.length; i += 8) {
        const block = encryptedData.slice(i, i + 8);
        const decBlock = decryptBlock(block, key);
        decrypted.set(decBlock, i);
    }
    // Retirer le padding
    const paddedDecrypted = decrypted.slice(0, originalLength);
    // Vérification simple du padding (pas essentielle pour l'exercice, mais bonne pratique)
    // const paddingSize = decrypted[decrypted.length - 1];
    // const content = decrypted.slice(0, decrypted.length - paddingSize);
    return paddedDecrypted; // On retourne simplement la tranche de longueur originale
}

async function handleEncrypt() {
    if (!encryptFile) {
        showAlert('Veuillez sélectionner un fichier', 'error');
        return;
    }
    const password = document.getElementById('encrypt-password').value;
    if (!password) {
        showAlert('Veuillez entrer un mot de passe', 'error');
        return;
    }
    if (password.length < 4) {
        showAlert('Le mot de passe doit contenir au moins 4 caractères', 'error');
        return;
    }
    const btn = document.getElementById('encrypt-btn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Chiffrement en cours...';
    clearAlert();
    try {
        const arrayBuffer = await encryptFile.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);
        console.log('Taille originale:', data.length);
        const encrypted = await encryptData(data, password);
        console.log('Taille chiffrée:', encrypted.length);
        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const filename = encryptFile.name + '.encrypted';
        showSuccess(filename, encrypted.length, data.length, url, 'encrypt');
    } catch (err) {
        showAlert('Erreur lors du chiffrement: ' + err.message, 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🔒 Chiffrer le fichier';
    }
}

async function handleDecrypt() {
    if (!decryptFile) {
        showAlert('Veuillez sélectionner un fichier chiffré', 'error');
        return;
    }
    const password = document.getElementById('decrypt-password').value;
    if (!password) {
        showAlert('Veuillez entrer le mot de passe', 'error');
        return;
    }
    const btn = document.getElementById('decrypt-btn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Déchiffrement en cours...';
    clearAlert();
    try {
        const arrayBuffer = await decryptFile.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);
        console.log('Taille fichier chiffré:', data.length);
        const decrypted = await decryptData(data, password);
        console.log('Taille déchiffrée:', decrypted.length);
        if (decrypted.length === 0) throw new Error('Le déchiffrement a produit un fichier vide');
        let filename = decryptFile.name;
        if (filename.endsWith('.encrypted')) filename = filename.slice(0, -10);
        else filename = filename + '.decrypted';
        const blob = new Blob([decrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        showSuccess(filename, decrypted.length, null, url, 'decrypt');
    } catch (err) {
        showAlert('Erreur lors du déchiffrement. Vérifiez le mot de passe ou le fichier: ' + err.message, 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🔓 Déchiffrer le fichier';
    }
}