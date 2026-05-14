const KEY_STORE = "secret-share-ecdh-v1";
const WARN_FILE_BYTES = 60 * 1024;
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

async function getOwnKeys() {
  const saved = localStorage.getItem(KEY_STORE);
  if (saved) {
    const parsed = JSON.parse(saved);
    return {
      privateKey: await crypto.subtle.importKey(
        "jwk",
        parsed.privateJwk,
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"]
      ),
      publicB64: parsed.publicB64
    };
  }

  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicB64 = bufferToBase64Url(await crypto.subtle.exportKey("raw", pair.publicKey));
  localStorage.setItem(KEY_STORE, JSON.stringify({ privateJwk, publicB64 }));
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
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256
  ));
  const material = concatBytes(enc.encode("secret-share-v1"), shared, ephemeralRaw, recipientRaw);
  const keyBytes = await crypto.subtle.digest("SHA-256", material);
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function emojiFingerprint(rawBytes) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", rawBytes));
  return Array.from(hash.slice(0, 6), (byte) => EMOJI[byte % EMOJI.length]).join(" ");
}

function appUrl(params) {
  const url = new URL(location.href);
  url.hash = "";
  url.search = "";
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    setStatus("Copied.");
  } catch {
    setStatus("Copy failed. Select the link and copy it manually.", true);
  }
}

function readFileAsBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

async function selectedPayload() {
  const file = $("secretFile").files[0];
  if (file) {
    const bytes = await readFileAsBytes(file);
    return {
      kind: "file",
      name: file.name || "secret-file",
      mime: file.type || "application/octet-stream",
      data: bytesToBase64Url(bytes)
    };
  }

  const text = $("secretText").value;
  if (!text) throw new Error("Type text or choose a file first.");
  return { kind: "text", text };
}

async function encryptForRecipient(recipientB64, payload) {
  const recipientRaw = base64UrlToBytes(recipientB64);
  const recipientPublic = await importPublicKey(recipientRaw);
  const ephemeral = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
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
    v: 1,
    e: bytesToBase64Url(ephemeralRaw),
    i: bytesToBase64Url(iv),
    c: bufferToBase64Url(ciphertext)
  }));
}

async function decryptPayload(recipientB64, dataB64) {
  const box = JSON.parse(base64UrlToUtf8(dataB64));
  if (box.v !== 1) throw new Error("Unsupported encrypted data version.");

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

  $("secretFile").onchange = () => {
    const file = $("secretFile").files[0];
    const warning = $("fileWarning");
    if (file && file.size > WARN_FILE_BYTES) {
      warning.textContent = "This will create a very long URL. Many apps and browsers reject URLs over roughly 100 KB.";
      show(warning);
    } else {
      show(warning, false);
    }
  };

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

    if (payload.kind === "file") {
      const blob = new Blob([base64UrlToBytes(payload.data)], { type: payload.mime });
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = payload.name || "secret-file";
      link.textContent = `Download ${link.download}`;
      $("decryptedFile").replaceChildren(link);
      show($("decryptedFile"));
      return;
    }

    throw new Error("Unknown decrypted data type.");
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

  ownKeys = await getOwnKeys();
  ownPublicB64 = ownKeys.publicB64;
  const ownRaw = base64UrlToBytes(ownPublicB64);
  $("myFingerprint").textContent = await emojiFingerprint(ownRaw);
  setupIdentity();

  const params = new URLSearchParams(location.search);
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

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}

init().catch((err) => setStatus(err.message || "Something went wrong.", true));
