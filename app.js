const DB_NAME = "droplock-keys";
const DB_STORE = "keys";
const DB_KEY = "identity";
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

function utf8ToBase64Url(value) {
  return bytesToBase64Url(enc.encode(value));
}

function base64UrlToUtf8(value) {
  return dec.decode(base64UrlToBytes(value));
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

function selectedPayload() {
  const text = $("secretText").value;
  if (!text) throw new Error("Type text first.");
  return { kind: "text", text };
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
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(JSON.stringify(payload))
  );
  return utf8ToBase64Url(JSON.stringify({
    e: bytesToBase64Url(ephemeralRaw),
    i: bytesToBase64Url(iv),
    c: bufferToBase64Url(ciphertext)
  }));
}

async function decryptPayload(recipientB64, dataB64) {
  const box = JSON.parse(base64UrlToUtf8(dataB64));

  const recipientRaw = base64UrlToBytes(recipientB64);
  const ephemeralRaw = base64UrlToBytes(box.e);
  const ephemeralPublic = await importPublicKey(ephemeralRaw);
  const aesKey = await deriveAesKey(ownKeys.privateKey, ephemeralPublic, ephemeralRaw, recipientRaw);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(box.i) },
    aesKey,
    base64UrlToBytes(box.c)
  );
  return JSON.parse(dec.decode(plaintext));
}

function setupIdentity() {
  const link = appUrl({ k: ownPublicB64 });
  $("requestLink").value = link;
  $("copyRequest").onclick = () => copyText(link);
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
      const dataB64 = await encryptForRecipient(recipientB64, payload);
      const link = appUrl({ k: recipientB64, d: dataB64 });
      $("encryptedLink").value = link;
      show($("result"));
      $("copyEncrypted").onclick = () => copyText(link);
      setStatus(`Encrypted. Link length: ${link.length.toLocaleString()} characters.`);
    } catch (err) {
      setStatus(err.message || "Encryption failed.", true);
    }
  };
}

async function setupDecrypt(recipientB64, dataB64) {
  show($("decrypt"));
  try {
    if (recipientB64 !== ownPublicB64) {
      throw new Error("This secret was not encrypted for this browser's saved key.");
    }
    const payload = await decryptPayload(recipientB64, dataB64);
    show($("decrypting"), false);

    if (payload.kind === "text") {
      $("decryptedText").textContent = payload.text;
      show($("decryptedText"));
      return;
    }

    throw new Error("Only text payloads are supported.");
  } catch (err) {
    show($("decrypting"), false);
    $("decryptError").textContent = err.message || "Decryption failed.";
    show($("decryptError"));
  }
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
  const dataB64 = params.get("d");

  if (recipientB64 && dataB64) {
    await setupDecrypt(recipientB64, dataB64);
  } else if (recipientB64) {
    await setupCompose(recipientB64);
  } else {
    show($("identity"));
  }
}

init().catch((err) => setStatus(err.message || "Something went wrong.", true));
