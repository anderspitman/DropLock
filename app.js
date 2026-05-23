const DB_NAME = "droplock-keys";
const DB_STORE = "keys";
const DB_KEY = "identity";
const MAGIC = new Uint8Array([0x44, 0x4c, 0x43, 0x4b]); // DLCK
const FORMAT_VERSION = 1;
const PUBLIC_KEY_BYTES = 65;
const IV_BYTES = 12;
const HEADER_BYTES = MAGIC.length + 1 + PUBLIC_KEY_BYTES + PUBLIC_KEY_BYTES + IV_BYTES;
const PAYLOAD_TEXT = 1;
const PAYLOAD_FILE = 2;
const MAX_URL_CHARS = 60000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);
const EMOJI = [
  "😀","😎","🥳","🤖","👻","🐶","🐱","🦊","🐻","🐼","🐸","🦁","🐵","🐧","🐢","🦋",
  "🌲","🌵","🌻","🍄","🍎","🍋","🍒","🥝","🍕","🍩","⚽","🎲","🎸","🚗","🚀","🛸",
  "🌙","⭐","☀️","⚡","🔥","❄️","🌈","☂️","💎","🔑","🔒","📦","📚","✏️","🎁","🎈",
  "❤️","🧡","💛","💚","💙","💜","🤍","🖤","✅","🔔","⏰","🧭","🏠","🌍","🧪","🧩"
];

let ownKeys;
let ownPublicB64;
let encryptedDownloadUrl;
let decryptedDownloadUrl;

function show(el, visible = true) {
  el.classList.toggle("hidden", !visible);
}

function setStatus(text, isError = false) {
  $("status").textContent = text;
  $("status").className = isError ? "status error" : "status";
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function bufferToBase64Url(buffer) {
  return bytesToBase64Url(new Uint8Array(buffer));
}

function base64UrlToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concatBytes(...parts) {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function assertPublicKeyBytes(rawBytes) {
  if (rawBytes.length !== PUBLIC_KEY_BYTES || rawBytes[0] !== 0x04) {
    throw new Error("Invalid public key.");
  }
}

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(DB_STORE, { keyPath: "id" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function loadStoredIdentity() {
  const db = await openKeyDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(DB_STORE, "readonly").objectStore(DB_STORE).get(DB_KEY);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

async function saveStoredIdentity(privateKey, publicB64) {
  const db = await openKeyDb();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(DB_STORE, "readwrite");
      tx.objectStore(DB_STORE).put({ id: DB_KEY, privateKey, publicB64 });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function getOwnKeys() {
  const saved = await loadStoredIdentity();
  if (saved?.privateKey && saved?.publicB64) {
    return { privateKey: saved.privateKey, publicB64: saved.publicB64 };
  }

  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const publicB64 = bufferToBase64Url(await crypto.subtle.exportKey("raw", pair.publicKey));
  await saveStoredIdentity(pair.privateKey, publicB64);
  return { privateKey: pair.privateKey, publicB64 };
}

async function importPublicKey(rawBytes) {
  assertPublicKeyBytes(rawBytes);
  return crypto.subtle.importKey(
    "raw",
    rawBytes,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
}

async function deriveAesKey(privateKey, publicKey, ephemeralRaw, recipientRaw) {
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: concatBytes(ephemeralRaw, recipientRaw),
      info: enc.encode("droplock aes-gcm")
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function emojiFingerprint(rawBytes) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", rawBytes));
  return Array.from(hash.slice(0, 16), (byte) => EMOJI[byte % EMOJI.length]).join(" ");
}

function appUrl(params) {
  const url = new URL(location.href);
  url.search = "";
  url.hash = new URLSearchParams(params).toString();
  return url.toString();
}

function appParams() {
  const fragment = location.hash.startsWith("#") ? location.hash.slice(1) : location.hash;
  return new URLSearchParams(fragment);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus("Copied.");
  } catch {
    setStatus("Copy failed. Select the link and copy it manually.", true);
  }
}

async function readFileAsBytes(file) {
  return new Uint8Array(await file.arrayBuffer());
}

async function selectedPayload() {
  const file = $("secretFile").files[0];
  if (file) {
    return {
      type: PAYLOAD_FILE,
      name: file.name || "file",
      mime: file.type || "application/octet-stream",
      data: await readFileAsBytes(file)
    };
  }

  const text = $("secretText").value;
  if (!text) throw new Error("Type text or choose a file first.");
  return { type: PAYLOAD_TEXT, name: "", mime: "text/plain;charset=utf-8", data: enc.encode(text) };
}

function encodePayload(payload) {
  const name = enc.encode(payload.name || "");
  const mime = enc.encode(payload.mime || "");
  if (name.length > 65535 || mime.length > 65535) {
    throw new Error("File metadata is too long.");
  }
  return concatBytes(
    Uint8Array.of(payload.type, name.length >> 8, name.length & 255, mime.length >> 8, mime.length & 255),
    name,
    mime,
    payload.data
  );
}

function decodePayload(bytes) {
  if (bytes.length < 5) throw new Error("Invalid plaintext payload.");
  const type = bytes[0];
  const nameLen = (bytes[1] << 8) | bytes[2];
  const mimeLen = (bytes[3] << 8) | bytes[4];
  const nameStart = 5;
  const mimeStart = nameStart + nameLen;
  const dataStart = mimeStart + mimeLen;
  if (dataStart > bytes.length) throw new Error("Invalid plaintext payload.");
  if (type !== PAYLOAD_TEXT && type !== PAYLOAD_FILE) throw new Error("Unsupported payload type.");

  return {
    type,
    name: dec.decode(bytes.slice(nameStart, mimeStart)),
    mime: dec.decode(bytes.slice(mimeStart, dataStart)),
    data: bytes.slice(dataStart)
  };
}

function buildHeader(recipientRaw, ephemeralRaw, iv) {
  assertPublicKeyBytes(recipientRaw);
  assertPublicKeyBytes(ephemeralRaw);
  const header = new Uint8Array(HEADER_BYTES);
  let offset = 0;
  header.set(MAGIC, offset);
  offset += MAGIC.length;
  header[offset++] = FORMAT_VERSION;
  header.set(recipientRaw, offset);
  offset += PUBLIC_KEY_BYTES;
  header.set(ephemeralRaw, offset);
  offset += PUBLIC_KEY_BYTES;
  header.set(iv, offset);
  return header;
}

function parseMessage(message) {
  if (message.length < HEADER_BYTES + 16) throw new Error("Invalid encrypted message.");
  for (let i = 0; i < MAGIC.length; i++) {
    if (message[i] !== MAGIC[i]) throw new Error("Invalid encrypted message.");
  }
  if (message[MAGIC.length] !== FORMAT_VERSION) throw new Error("Unsupported message format.");

  let offset = MAGIC.length + 1;
  const recipientRaw = message.slice(offset, offset + PUBLIC_KEY_BYTES);
  offset += PUBLIC_KEY_BYTES;
  const ephemeralRaw = message.slice(offset, offset + PUBLIC_KEY_BYTES);
  offset += PUBLIC_KEY_BYTES;
  const iv = message.slice(offset, offset + IV_BYTES);
  assertPublicKeyBytes(recipientRaw);
  assertPublicKeyBytes(ephemeralRaw);

  return {
    header: message.slice(0, HEADER_BYTES),
    recipientRaw,
    ephemeralRaw,
    iv,
    ciphertext: message.slice(HEADER_BYTES)
  };
}

async function encryptForRecipient(recipientB64, payload) {
  const recipientRaw = base64UrlToBytes(recipientB64);
  const recipientPublic = await importPublicKey(recipientRaw);
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"]
  );
  const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  const aesKey = await deriveAesKey(ephemeral.privateKey, recipientPublic, ephemeralRaw, recipientRaw);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const header = buildHeader(recipientRaw, ephemeralRaw, iv);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: header },
    aesKey,
    encodePayload(payload)
  ));
  return concatBytes(header, ciphertext);
}

async function decryptMessage(messageBytes) {
  const message = parseMessage(messageBytes);
  const ownRaw = base64UrlToBytes(ownPublicB64);
  if (!equalBytes(message.recipientRaw, ownRaw)) {
    throw new Error("This message was not encrypted for this browser's saved key.");
  }

  const ephemeralPublic = await importPublicKey(message.ephemeralRaw);
  const aesKey = await deriveAesKey(ownKeys.privateKey, ephemeralPublic, message.ephemeralRaw, message.recipientRaw);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: message.iv, additionalData: message.header },
    aesKey,
    message.ciphertext
  );
  return decodePayload(new Uint8Array(plaintext));
}

function displayPayload(payload) {
  if (payload.type === PAYLOAD_TEXT) {
    $("decryptedText").textContent = dec.decode(payload.data);
    show($("decryptedText"));
    return;
  }

  if (decryptedDownloadUrl) URL.revokeObjectURL(decryptedDownloadUrl);
  const blob = new Blob([payload.data], { type: payload.mime || "application/octet-stream" });
  decryptedDownloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = decryptedDownloadUrl;
  link.download = payload.name || "droplock-file";
  link.textContent = `Download ${link.download}`;
  link.className = "buttonLink";
  $("decryptedFile").replaceChildren(link);
  show($("decryptedFile"));
}

async function decryptAndDisplay(messageBytes) {
  show($("decrypt"));
  show($("decrypting"));
  show($("decryptedText"), false);
  show($("decryptedFile"), false);
  show($("decryptError"), false);
  $("decryptedText").textContent = "";
  $("decryptedFile").replaceChildren();
  if (decryptedDownloadUrl) {
    URL.revokeObjectURL(decryptedDownloadUrl);
    decryptedDownloadUrl = undefined;
  }

  try {
    const payload = await decryptMessage(messageBytes);
    show($("decrypting"), false);
    displayPayload(payload);
    setStatus("Decrypted.");
  } catch (err) {
    show($("decrypting"), false);
    $("decryptError").textContent = err.message || "Decryption failed.";
    show($("decryptError"));
  }
}

function setupIdentity() {
  const link = appUrl({ k: ownPublicB64 });
  $("requestLink").value = link;
  $("copyRequest").onclick = () => copyText(link);

  $("encryptedFile").onchange = async () => {
    const file = $("encryptedFile").files[0];
    if (!file) return;
    setStatus("Decrypting...");
    await decryptAndDisplay(await readFileAsBytes(file));
  };
}

function encryptedFileName() {
  return "message.droplock";
}

async function setupCompose(recipientB64) {
  show($("compose"));
  const recipientRaw = base64UrlToBytes(recipientB64);
  await importPublicKey(recipientRaw);
  $("recipientFingerprint").textContent = await emojiFingerprint(recipientRaw);

  $("generateLink").onclick = async () => {
    try {
      setStatus("Encrypting...");
      const payload = await selectedPayload();
      const messageBytes = await encryptForRecipient(recipientB64, payload);
      const dataChars = Math.ceil(messageBytes.length * 4 / 3);
      const downloadName = encryptedFileName();

      if (encryptedDownloadUrl) URL.revokeObjectURL(encryptedDownloadUrl);
      encryptedDownloadUrl = URL.createObjectURL(new Blob([messageBytes], { type: "application/octet-stream" }));
      $("downloadEncrypted").href = encryptedDownloadUrl;
      $("downloadEncrypted").download = downloadName;
      $("downloadEncrypted").textContent = `Download ${downloadName}`;

      const maxDataChars = MAX_URL_CHARS - appUrl({ m: "" }).length;
      if (dataChars <= maxDataChars) {
        const link = appUrl({ m: bytesToBase64Url(messageBytes) });
        $("encryptedLink").value = link;
        show($("linkResult"));
        show($("linkTooLarge"), false);
        $("copyEncrypted").onclick = () => copyText(link);
        setStatus(`Encrypted. Link length: ${link.length.toLocaleString()} characters.`);
      } else {
        $("encryptedLink").value = "";
        show($("linkResult"), false);
        $("linkTooLarge").textContent = "Too large for a practical URL. Send the .droplock file instead.";
        show($("linkTooLarge"));
        setStatus("Encrypted. Send the .droplock file.");
      }

      $("secretText").value = "";
      $("secretFile").value = "";
      show($("result"));
    } catch (err) {
      setStatus(err.message || "Encryption failed.", true);
    }
  };
}

async function setupDecrypt(dataB64) {
  await decryptAndDisplay(base64UrlToBytes(dataB64));
}

async function init() {
  if (!crypto.subtle) {
    setStatus("WebCrypto is unavailable. Use HTTPS or localhost.", true);
    return;
  }
  if (!("indexedDB" in window)) {
    setStatus("IndexedDB is unavailable, so this browser cannot save non-extractable keys.", true);
    return;
  }

  ownKeys = await getOwnKeys();
  ownPublicB64 = ownKeys.publicB64;
  const ownRaw = base64UrlToBytes(ownPublicB64);
  $("myFingerprint").textContent = await emojiFingerprint(ownRaw);
  setupIdentity();

  const params = appParams();
  const recipientB64 = params.get("k");
  const messageB64 = params.get("m");

  if (messageB64) {
    await setupDecrypt(messageB64);
  } else if (recipientB64) {
    await setupCompose(recipientB64);
  } else {
    show($("identity"));
  }
}

init().catch((err) => setStatus(err.message || "Something went wrong.", true));
