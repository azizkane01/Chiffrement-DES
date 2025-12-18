// ========= PARTIE 1 : CONSTANTES ET GESTION DE L'INTERFACE =========
// PERSONNE 1 : Présente les tables DES, les constantes et les fonctions d'interface (UI).

let encryptFile = null;
let decryptFile = null;

// Tables DES (S-Box, Permutations, etc.)
const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 46, 56, 42, 50, 36, 29, 32];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
];

// Gestion des Onglets
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

// Gestion de la sélection de fichier
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

// Gestion de l'affichage du selecteur de Mode (Visible seulement pour DES)
function toggleModeSelect() {
    const algo = document.getElementById('algorithm-select').value;
    const modeGroup = document.getElementById('mode-group');
    if (algo === 'DES') {
        modeGroup.style.display = 'block';
    } else {
        modeGroup.style.display = 'none';
    }
}

function toggleDecryptModeSelect() {
    const algo = document.getElementById('decrypt-algorithm-select').value;
    const modeGroup = document.getElementById('decrypt-mode-group');
    if (algo === 'DES') {
        modeGroup.style.display = 'block';
    } else {
        modeGroup.style.display = 'none';
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


// ========= PARTIE 2 : OUTILS BINAIRES ET GÉNÉRATION DE CLÉS =========
// PERSONNE 2 : Présente la manipulation des bits, la gestion de l'IV et la génération des clés (Schedule DES & WebCrypto AES).

// Génération de clé DES via hachage SHA-256 (64 premiers bits)
async function generateDESKey(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hash = new Uint8Array(hashBuffer);
    return new Uint8Array(hash.slice(0, 8)); // 64 bits
}

// Génération de clé AES via Web Crypto API (PBKDF2 pour sécurité)
async function generateAESKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Outils de manipulation de bits pour DES
function bytesToBits(bytes) {
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let j = 7; j >= 0; j--) {
            bits.push((bytes[i] >> j) & 1);
        }
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

function permute(input, table) {
    const output = [];
    for (let i = 0; i < table.length; i++) output.push(input[table[i] - 1]);
    return output;
}

function leftShift(bits, n) {
    return bits.slice(n).concat(bits.slice(0, n));
}

function xor(a, b) {
    const result = [];
    for (let i = 0; i < a.length; i++) result.push(a[i] ^ b[i]);
    return result;
}

// Génération des sous-clés DES
function generateSubkeys(key) {
    const keyBits = bytesToBits(key);
    const permutedKey = permute(keyBits, PC1);
    let C = permutedKey.slice(0, 28);
    let D = permutedKey.slice(28, 56);
    const subkeys = [];
    for (let i = 0; i < 16; i++) {
        C = leftShift(C, SHIFTS[i]);
        D = leftShift(D, SHIFTS[i]);
        subkeys.push(permute(C.concat(D), PC2));
    }
    return subkeys;
}


// ========= PARTIE 3 : CŒUR ALGORITHMIQUE (DES) =========
// PERSONNE 3 : Présente la logique pure du DES : Fonction de Feistel, S-Box et le chiffrement de bloc.

function sboxLookup(input) {
    const output = [];
    for (let i = 0; i < 8; i++) {
        const block = input.slice(i * 6, (i + 1) * 6);
        const row = (block[0] << 1) | block[5];
        const col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4];
        const val = SBOXES[i][row][col];
        for (let j = 3; j >= 0; j--) output.push((val >> j) & 1);
    }
    return output;
}

function fFunction(right, subkey) {
    const expanded = permute(right, E);
    const xored = xor(expanded, subkey);
    const sboxOutput = sboxLookup(xored);
    return permute(sboxOutput, P);
}

function desProcessBlock(block, subkeys) {
    const bits = bytesToBits(block);
    const permuted = permute(bits, IP);
    let left = permuted.slice(0, 32);
    let right = permuted.slice(32, 64);
    for (let i = 0; i < 16; i++) {
        const temp = right.slice();
        const fResult = fFunction(right, subkeys[i]);
        right = xor(left, fResult);
        left = temp;
    }
    return bitsToBytes(permute(right.concat(left), IP_INV));
}

function encryptBlock(block, key) {
    return desProcessBlock(block, generateSubkeys(key));
}

function decryptBlock(block, key) {
    return desProcessBlock(block, generateSubkeys(key).reverse());
}


// ========= PARTIE 4 : MODES OPERATOIRES (ECB/CBC/AES) ET EVENTS =========
// PERSONNE 4 : Présente l'implémentation des modes ECB/CBC, l'intégration AES et les gestionnaires d'événements.

// --- Implémentation DES (ECB & CBC) ---

async function encryptDataDES(data, password, mode) {
    const key = await generateDESKey(password);
    const originalLength = data.length;

    // Padding
    const paddingSize = 8 - (data.length % 8) || 8;
    const paddedLength = data.length + paddingSize;
    const padded = new Uint8Array(paddedLength);
    padded.set(data);
    for (let i = data.length; i < paddedLength; i++) padded[i] = paddingSize;

    const encrypted = new Uint8Array(paddedLength);
    let iv = new Uint8Array(8); // IV vide par défaut pour ECB (Note: ECB n'utilise pas d'IV techniquement, mais pour simplifier la structure de fichier)

    // Si CBC, générer un IV aléatoire
    if (mode === 'CBC') {
        crypto.getRandomValues(iv);
    }

    let previousBlock = iv; // Previous block sert d'IV initialement pour CBC

    for (let i = 0; i < paddedLength; i += 8) {
        let block = padded.slice(i, i + 8);

        if (mode === 'CBC') {
            // CBC: XOR avec le bloc chiffré précédent (ou IV) AVANT chiffrement
            // Conversion en bits pour XOR manuel
            const blockBits = bytesToBits(block);
            const prevBits = bytesToBits(previousBlock);
            const xoredBits = xor(blockBits, prevBits);
            block = bitsToBytes(xoredBits);
        }

        const encryptedBlock = encryptBlock(block, key);
        encrypted.set(encryptedBlock, i);

        // Mise à jour du bloc précédent pour CBC
        previousBlock = encryptedBlock;
    }

    // Header: [4 bytes Taille] [8 bytes IV]
    const result = new Uint8Array(4 + 8 + encrypted.length);
    // Taille
    result[0] = (originalLength >> 24) & 0xff;
    result[1] = (originalLength >> 16) & 0xff;
    result[2] = (originalLength >> 8) & 0xff;
    result[3] = originalLength & 0xff;
    // IV (sera des zéros si ECB, mais on le stocke quand même pour uniformité ou on pourrait l'omettre)
    // Pour simplifier le déchiffrement, on inclut toujours l'IV field, même si inutilisé en ECB.
    result.set(iv, 4);
    // Données
    result.set(encrypted, 12);

    return result;
}

async function decryptDataDES(data, password, mode) {
    if (data.length < 12) throw new Error('Fichier trop court');

    const originalLength = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    const iv = data.slice(4, 12);
    const encryptedData = data.slice(12);

    if (encryptedData.length % 8 !== 0) throw new Error('Données corrompues');

    const key = await generateDESKey(password);
    const decrypted = new Uint8Array(encryptedData.length);
    let previousBlock = iv;

    for (let i = 0; i < encryptedData.length; i += 8) {
        const block = encryptedData.slice(i, i + 8);
        const decBlock = decryptBlock(block, key); // Déchiffrement brut

        if (mode === 'CBC') {
            // CBC: XOR avec le bloc chiffré précédent (ou IV) APRÈS déchiffrement
            const decBits = bytesToBits(decBlock);
            const prevBits = bytesToBits(previousBlock);
            const xoredBits = xor(decBits, prevBits);
            decrypted.set(bitsToBytes(xoredBits), i);
            previousBlock = block; // Le ciphertext actuel devient le IV du prochain
        } else {
            // ECB
            decrypted.set(decBlock, i);
        }
    }

    return decrypted.slice(0, originalLength); // Coupe le padding
}

// --- Implémentation AES (Utilisation API Web Crypto) ---

async function encryptDataAES(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16)); // Salt pour la clé
    const key = await generateAESKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12)); // IV recommand pour GCM

    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );

    // Format fichier AES: [16 bytes Salt] [12 bytes IV] [Données Chiffrées]
    // Note: AES-GCM gère l'intégrité et la taille, mais on peut garder notre logique de taille originale si besoin.
    // Web Crypto ne padde pas manuel en GCM (stream cipher mode), donc la taille est préservée (plus auth tag).
    // On va stocker simplement tout ce qu'il faut.

    const result = new Uint8Array(salt.length + iv.length + encryptedContent.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encryptedContent), salt.length + iv.length);

    return result;
}

async function decryptDataAES(data, password) {
    if (data.length < 28) throw new Error('Fichier invalide');

    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const encryptedContent = data.slice(28);

    const key = await generateAESKey(password, salt);

    try {
        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedContent
        );
        return new Uint8Array(decryptedContent);
    } catch (e) {
        throw new Error("Échec du déchiffrement AES (Mot de passe incorrect ou fichier altéré)");
    }
}


// --- Main Handlers ---

async function handleEncrypt() {
    if (!encryptFile) { showAlert('Veuillez sélectionner un fichier', 'error'); return; }

    const password = document.getElementById('encrypt-password').value;
    if (!password || password.length < 4) { showAlert('Mot de passe invalide (min 4 chars)', 'error'); return; }

    const algo = document.getElementById('algorithm-select').value;
    const mode = document.getElementById('mode-select').value;

    const btn = document.getElementById('encrypt-btn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Chiffrement en cours...';

    try {
        const arrayBuffer = await encryptFile.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);

        let encrypted;
        if (algo === 'AES') {
            encrypted = await encryptDataAES(data, password);
        } else {
            encrypted = await encryptDataDES(data, password, mode);
        }

        const blob = new Blob([encrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        showSuccess(encryptFile.name + '.encrypted', encrypted.length, data.length, url, 'encrypt');
    } catch (err) {
        showAlert('Erreur: ' + err.message, 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🔒 Chiffrer le fichier';
        document.getElementById('encrypt-password').value = '';
    }
}

async function handleDecrypt() {
    if (!decryptFile) { showAlert('Veuillez sélectionner un fichier', 'error'); return; }

    const password = document.getElementById('decrypt-password').value;
    if (!password) { showAlert('Mot de passe requis', 'error'); return; }

    const algo = document.getElementById('decrypt-algorithm-select').value;
    const mode = document.getElementById('decrypt-mode-select').value;

    const btn = document.getElementById('decrypt-btn');
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Déchiffrement en cours...';

    try {
        const arrayBuffer = await decryptFile.arrayBuffer();
        const data = new Uint8Array(arrayBuffer);

        let decrypted;
        if (algo === 'AES') {
            decrypted = await decryptDataAES(data, password);
        } else {
            decrypted = await decryptDataDES(data, password, mode);
        }

        let filename = decryptFile.name.replace('.encrypted', '') || 'decrypted_file';
        const blob = new Blob([decrypted], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        showSuccess(filename, decrypted.length, null, url, 'decrypt');
    } catch (err) {
        showAlert('Erreur: ' + err.message, 'error');
        console.error(err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '🔓 Déchiffrer le fichier';
        document.getElementById('decrypt-password').value = '';
    }
}
