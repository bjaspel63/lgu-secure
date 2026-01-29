/* =========================================================
  OFFLINE BARANGAY RECORDS
  - Chained ledger (prevHash)
  - New records are signed (Ed25519)
  - Corrections/Revoke are append-only records referencing an ISSUE
  - Daily signed summary (export/print)
  - Offline login + roles
  RULES:
    - Only ADMIN can unlock signing.
    - STAFF can Issue/Correct/Revoke only while signing is unlocked.
========================================================= */

// -----------------------
// STORAGE KEYS
// -----------------------
const LS_KEY_V2   = "brgy_ledger_v2_print";       // your old key
const LS_KEY      = "brgy_ledger_v2_print";       // keep same so you don't lose data
const META_KEY    = "brgy_meta_v3";
const USERS_KEY   = "brgy_users_v1";
const SESSION_KEY = "brgy_session_v1";

// -----------------------
// STATE
// -----------------------
let ledger = loadLedger();
let lastIssued = null;

let META = loadMeta();

let UNLOCKED_SECRET_B64 = null; // in-memory only
let SIGNING_UNLOCKED = false;
let SIGNING_UNLOCKED_BY = null;

let selectedRecordId = null;
let lastSummary = null;

// -----------------------
// HELPERS
// -----------------------
function escapeHtml(s){
  return String(s ?? "").replace(/[&<>"']/g, m => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[m]));
}
function shortHash(h){
  if(!h) return "";
  return h.slice(0,10) + "…" + h.slice(-8);
}
function setIssueStatus(msg, ok=true){
  const el = document.getElementById("issueStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}
function setVerifyStatus(msg, ok=true){
  const el = document.getElementById("verifyStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}
function setChainStatus(msg, ok=true){
  const el = document.getElementById("chainStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}
function setActionStatus(msg, ok=true){
  const el = document.getElementById("actionStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}
function setSummaryStatus(msg, ok=true){
  const el = document.getElementById("summaryStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}

function uid(){
  const s = crypto.getRandomValues(new Uint8Array(8));
  return [...s].map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();
}
async function sha256(text){
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join("");
}

// base64 helpers
function u8ToB64(u8){
  let s = "";
  u8.forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}
function b64ToU8(b64){
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// -----------------------
// LEDGER LOAD/SAVE
// -----------------------
function normalizeLedgerFormat(arr){
  // Keep your existing records as "v2" (legacy) so their hash recompute still matches.
  // New records will be "v3" with type/refId/pub/sig.
  return arr.map((r, i) => {
    const out = {...r};

    // Ensure index exists
    if(typeof out.index !== "number") out.index = i;

    // genesis defaults
    if(out.index === 0){
      out.type = out.type || "GENESIS";
      out.format = out.format || "v2";
      out.sig = out.sig || "";
      out.pub = out.pub || "";
      return out;
    }

    // legacy v2: no "type" field in your old code
    if(!out.type){
      out.type = "ISSUE";
    }
    if(!out.format){
      // if it already has sig/pub we treat it as v3, else v2
      out.format = (out.sig && out.pub) ? "v3" : "v2";
    }
    out.sig = out.sig || "";
    out.pub = out.pub || "";
    out.refId = out.refId || "";
    return out;
  });
}

function loadLedger(){
  try{
    const raw = localStorage.getItem(LS_KEY);
    if(!raw){
      return [{
        index: 0,
        type: "GENESIS",
        format: "v2",
        id: "GENESIS",
        name: "SYSTEM",
        doctype: "GENESIS",
        purpose: "Initial block",
        timestamp: new Date().toISOString(),
        prevHash: "0".repeat(64),
        hash: "0".repeat(64),
        sig: "",
        pub: "",
        refId: ""
      }];
    }
    return normalizeLedgerFormat(JSON.parse(raw));
  }catch{
    return [{
      index: 0,
      type: "GENESIS",
      format: "v2",
      id: "GENESIS",
      name: "SYSTEM",
      doctype: "GENESIS",
      purpose: "Initial block",
      timestamp: new Date().toISOString(),
      prevHash: "0".repeat(64),
      hash: "0".repeat(64),
      sig: "",
      pub: "",
      refId: ""
    }];
  }
}
function saveLedger(){
  localStorage.setItem(LS_KEY, JSON.stringify(ledger));
}

// -----------------------
// META (signing keys/settings)
// -----------------------
function loadMeta(){
  try{ return JSON.parse(localStorage.getItem(META_KEY) || "{}"); }catch{ return {}; }
}
function saveMeta(meta){
  localStorage.setItem(META_KEY, JSON.stringify(meta));
}

// -----------------------
// RECORD STRING (v2 vs v3)
// -----------------------
function buildRecordStringV2(rec){
  return [rec.id, rec.name, rec.doctype, rec.purpose, rec.timestamp, rec.prevHash].join("|");
}
function buildRecordStringV3(rec){
  return [
    rec.type || "ISSUE",
    rec.id,
    rec.refId || "",
    rec.name || "",
    rec.doctype || "",
    rec.purpose || "",
    rec.timestamp || "",
    rec.prevHash || "",
    rec.pub || ""
  ].join("|");
}
function buildRecordString(rec){
  return (rec.format === "v3") ? buildRecordStringV3(rec) : buildRecordStringV2(rec);
}

// -----------------------
// SIGN / VERIFY (Ed25519)
// -----------------------
function signHashB64(hashHex, secretKeyB64){
  const msg = new TextEncoder().encode(hashHex);
  const sk = b64ToU8(secretKeyB64);
  const sig = nacl.sign.detached(msg, sk);
  return u8ToB64(sig);
}
function verifyHashSig(hashHex, sigB64, publicKeyB64){
  try{
    const msg = new TextEncoder().encode(hashHex);
    const sig = b64ToU8(sigB64);
    const pk  = b64ToU8(publicKeyB64);
    return nacl.sign.detached.verify(msg, sig, pk);
  }catch{
    return false;
  }
}

// -----------------------
// ENCRYPT/DECRYPT PRIVATE KEY (AES-GCM + PBKDF2)
// -----------------------
async function pbkdf2Key(pass, saltU8){
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name:"PBKDF2", salt:saltU8, iterations:150000, hash:"SHA-256"},
    baseKey,
    {name:"AES-GCM", length:256},
    false,
    ["encrypt","decrypt"]
  );
}
async function encryptSecret(pass, secretB64){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await pbkdf2Key(pass, salt);
  const data = b64ToU8(secretB64);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data));
  return { salt:u8ToB64(salt), iv:u8ToB64(iv), ct:u8ToB64(ct) };
}
async function decryptSecret(pass, enc){
  const salt = b64ToU8(enc.salt);
  const iv   = b64ToU8(enc.iv);
  const ct   = b64ToU8(enc.ct);
  const key  = await pbkdf2Key(pass, salt);
  const pt   = new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, ct));
  return u8ToB64(pt);
}
async function ensureKeypair(){
  META = loadMeta();
  if(META.publicKeyB64 && META.encryptedSecret) return;

  const pass = prompt("First-time signing setup:\nCreate an ADMIN signing passphrase.\n(Min 6 characters)");
  if(!pass || pass.length < 6){
    alert("Passphrase too short (min 6).");
    throw new Error("No passphrase");
  }

  const kp = nacl.sign.keyPair();
  const publicKeyB64 = u8ToB64(kp.publicKey);
  const secretKeyB64 = u8ToB64(kp.secretKey);

  META.publicKeyB64 = publicKeyB64;
  META.encryptedSecret = await encryptSecret(pass, secretKeyB64);
  saveMeta(META);

  alert("Signing keys created.");
}
function lockSigning(){
  UNLOCKED_SECRET_B64 = null;
  SIGNING_UNLOCKED = false;
  SIGNING_UNLOCKED_BY = null;
}

// Only ADMIN can unlock signing
async function unlockSigningAdmin(){
  const sess = currentUser();
  if(!sess){ alert("Please login first."); return false; }
  if(sess.role !== "ADMIN"){ alert("Only ADMIN can unlock signing."); return false; }

  META = loadMeta();
  if(!META.encryptedSecret) await ensureKeypair();

  if(UNLOCKED_SECRET_B64){
    SIGNING_UNLOCKED = true;
    SIGNING_UNLOCKED_BY = sess.username;
    return true;
  }

  const pass = prompt("ADMIN: Enter signing passphrase to unlock:");
  if(!pass) return false;

  try{
    UNLOCKED_SECRET_B64 = await decryptSecret(pass, META.encryptedSecret);
    SIGNING_UNLOCKED = true;
    SIGNING_UNLOCKED_BY = sess.username;
    return true;
  }catch{
    alert("Wrong passphrase.");
    return false;
  }
}

// -----------------------
// LOGIN SYSTEM (LOCAL)
// -----------------------
function loadUsers(){
  try{ return JSON.parse(localStorage.getItem(USERS_KEY) || "[]"); }catch{ return []; }
}
function saveUsers(users){
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}
function getSession(){
  try{ return JSON.parse(localStorage.getItem(SESSION_KEY) || "null"); }catch{ return null; }
}
function setSession(sess){
  localStorage.setItem(SESSION_KEY, JSON.stringify(sess));
}
function clearSession(){
  localStorage.removeItem(SESSION_KEY);
}
function currentUser(){ return getSession(); }

function setLoginStatus(msg, ok=true){
  const el = document.getElementById("loginStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}
function setPassStatus(msg, ok=true){
  const el = document.getElementById("passStatus");
  el.innerHTML = ok ? msg : `<span class="no">${msg}</span>`;
}

async function pbkdf2Hash(password, saltU8, iterations=150000){
  const baseKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {name:"PBKDF2", salt:saltU8, iterations, hash:"SHA-256"},
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

async function createFirstAdminIfNeeded(){
  const users = loadUsers();
  const hasAdmin = users.some(u=>u.role==="ADMIN");
  document.getElementById("firstAdminHint").style.display = hasAdmin ? "none" : "block";
}

async function ensureAdminOnFirstLogin(username, password){
  const users = loadUsers();
  const hasAdmin = users.some(u=>u.role==="ADMIN");
  if(hasAdmin) return null;

  if(username !== "admin") throw new Error('First-time setup: username must be "admin".');
  if(!password || password.length < 6) throw new Error("Password too short (min 6).");

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2Hash(password, salt);

  const newAdmin = {
    username: "admin",
    role: "ADMIN",
    saltB64: u8ToB64(salt),
    hashB64: u8ToB64(hash),
    createdAt: new Date().toISOString()
  };
  users.push(newAdmin);
  saveUsers(users);
  return newAdmin;
}

async function verifyLogin(username, password){
  const users = loadUsers();
  const u = users.find(x => x.username.toLowerCase() === username.toLowerCase());
  if(!u) return null;

  const salt = b64ToU8(u.saltB64);
  const hash = await pbkdf2Hash(password, salt);
  return (u8ToB64(hash) === u.hashB64) ? u : null;
}

// Open/Close modals
function openLogin(){
  document.getElementById("loginOverlay").style.display = "flex";
  document.getElementById("loginUser").focus();
  createFirstAdminIfNeeded();
  setLoginStatus("Ready.");
}
function closeLogin(){
  document.getElementById("loginOverlay").style.display = "none";
  document.getElementById("loginPass").value = "";
}

function openPass(){
  document.getElementById("passOverlay").style.display = "flex";
  setPassStatus("Ready.");
  document.getElementById("curPass").focus();
}
function closePass(){
  document.getElementById("passOverlay").style.display = "none";
  document.getElementById("curPass").value = "";
  document.getElementById("newPass").value = "";
  document.getElementById("newPass2").value = "";
}

// Change own password
async function changeOwnPassword(curPass, newPass){
  const sess = currentUser();
  if(!sess) throw new Error("Not logged in.");

  const users = loadUsers();
  const idx = users.findIndex(u => u.username.toLowerCase() === sess.username.toLowerCase());
  if(idx < 0) throw new Error("User not found.");

  const u = users[idx];
  const salt = b64ToU8(u.saltB64);
  const hash = await pbkdf2Hash(curPass, salt);
  if(u8ToB64(hash) !== u.hashB64) throw new Error("Current password is incorrect.");

  if(!newPass || newPass.length < 6) throw new Error("New password too short (min 6).");

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newHash = await pbkdf2Hash(newPass, newSalt);

  users[idx] = {
    ...u,
    saltB64: u8ToB64(newSalt),
    hashB64: u8ToB64(newHash),
    updatedAt: new Date().toISOString()
  };
  saveUsers(users);
}

// Admin reset another user's password
async function adminResetUserPassword(username, newPass){
  const sess = currentUser();
  if(!sess || sess.role !== "ADMIN") throw new Error("Admin only.");

  const users = loadUsers();
  const idx = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
  if(idx < 0) throw new Error("User not found.");

  if(!newPass || newPass.length < 6) throw new Error("Password too short (min 6).");

  const newSalt = crypto.getRandomValues(new Uint8Array(16));
  const newHash = await pbkdf2Hash(newPass, newSalt);

  users[idx] = {
    ...users[idx],
    saltB64: u8ToB64(newSalt),
    hashB64: u8ToB64(newHash),
    updatedAt: new Date().toISOString()
  };
  saveUsers(users);
}

// -----------------------
// ROLE UI + GATES
// -----------------------
function canStaffAction(){
  const sess = currentUser();
  const isStaffOrAdmin = sess && (sess.role === "ADMIN" || sess.role === "STAFF");
  return !!(isStaffOrAdmin && SIGNING_UNLOCKED && UNLOCKED_SECRET_B64);
}
function isAdmin(){
  const sess = currentUser();
  return !!(sess && sess.role === "ADMIN");
}

function applyRoleUI(){
  const sess = currentUser();

  const badge = document.getElementById("userBadge");
  const loginBtn = document.getElementById("loginBtn");
  const logoutBtn = document.getElementById("logoutBtn");
  const changePassBtn = document.getElementById("changePassBtn");

  const addUserBtn = document.getElementById("addUserBtn");
  const resetUserBtn = document.getElementById("resetUserBtn");

  const unlockBtn = document.getElementById("unlockSignBtn");
  const lockBtn = document.getElementById("lockSignBtn");

  const issueBtn = document.getElementById("issueBtn");
  const correctBtn = document.getElementById("correctBtn");
  const revokeBtn = document.getElementById("revokeBtn");

  const exportBtn = document.getElementById("exportBtn");
  const importBtn = document.getElementById("importBtn");
  const clearLedgerBtn = document.getElementById("clearLedgerBtn");
  const tamperBtn = document.getElementById("tamperBtn");

  const genSummaryBtn = document.getElementById("genSummaryBtn");

  if(!sess){
    badge.textContent = "Not logged in";
    loginBtn.style.display = "";
    logoutBtn.style.display = "none";
    changePassBtn.style.display = "none";

    addUserBtn.style.display = "none";
    resetUserBtn.style.display = "none";
    unlockBtn.style.display = "none";
    lockBtn.style.display = "none";
  }else{
    const signState = SIGNING_UNLOCKED ? "SIGNING: UNLOCKED" : "SIGNING: LOCKED";
    badge.innerHTML = `<b>${escapeHtml(sess.username)}</b> · ${escapeHtml(sess.role)} · ${signState}`;
    loginBtn.style.display = "none";
    logoutBtn.style.display = "";
    changePassBtn.style.display = "";

    addUserBtn.style.display = (sess.role === "ADMIN") ? "" : "none";
    resetUserBtn.style.display = (sess.role === "ADMIN") ? "" : "none";

    unlockBtn.style.display = (sess.role === "ADMIN" && !SIGNING_UNLOCKED) ? "" : "none";
    lockBtn.style.display   = (sess.role === "ADMIN" && SIGNING_UNLOCKED) ? "" : "none";
  }

  // Staff actions require signing unlocked
  const allowStaff = canStaffAction();
  issueBtn.disabled = !allowStaff;
  correctBtn.disabled = !allowStaff;
  revokeBtn.disabled = !allowStaff;

  // Admin-only tools
  const admin = isAdmin();
  exportBtn.disabled = !admin;
  importBtn.disabled = !admin;
  clearLedgerBtn.disabled = !admin;
  tamperBtn.disabled = !admin;

  // Daily summary: admin only (and unlocked)
  genSummaryBtn.disabled = !(admin && SIGNING_UNLOCKED && UNLOCKED_SECRET_B64);
}

// -----------------------
// RENDER LEDGER
// -----------------------
function renderLedger(){
  const tbody = document.querySelector("#ledgerTable tbody");
  tbody.innerHTML = "";

  for(let i=0;i<ledger.length;i++){
    const r = ledger[i];
    const tr = document.createElement("tr");
    tr.dataset.index = String(i);

    tr.innerHTML = `
      <td>${r.index}</td>
      <td class="mono">${escapeHtml(r.id)}</td>
      <td>${escapeHtml(r.name || "")}</td>
      <td>${escapeHtml(r.doctype || "")}</td>
      <td class="mono">${shortHash(r.hash)}</td>
      <td class="mono">${shortHash(r.prevHash)}</td>
      <td><span class="tag" data-integrity="${i}">—</span></td>
    `;
    tbody.appendChild(tr);
  }
}
function updateIntegrityBadges(results){
  results.forEach((ok, i)=>{
    const badge = document.querySelector(`[data-integrity="${i}"]`);
    if(!badge) return;
    badge.classList.remove("good","bad");
    badge.classList.add(ok ? "good" : "bad");
    badge.textContent = ok ? "OK" : "BROKEN";
  });
}
async function chainCheck(){
  ledger = normalizeLedgerFormat(ledger);

  const res = new Array(ledger.length).fill(true);

  for(let i=1;i<ledger.length;i++){
    const prev = ledger[i-1];
    const cur  = ledger[i];

    // link check
    if(cur.prevHash !== prev.hash){
      res[i] = false;
      continue;
    }

    // hash check (v2/v3)
    const recomputed = await sha256(buildRecordString(cur));
    if(recomputed !== cur.hash){
      res[i] = false;
      continue;
    }

    // signature check: required only for v3 records
    if(cur.format === "v3" && cur.type !== "GENESIS"){
      const pub = cur.pub || loadMeta().publicKeyB64;
      if(!cur.sig || !pub || !verifyHashSig(cur.hash, cur.sig, pub)){
        res[i] = false;
      }
    }
  }

  res[0] = true;
  updateIntegrityBadges(res);

  const broken = res.filter(x=>!x).length;
  if(broken === 0){
    setChainStatus(`<span class="ok">✅ Chain OK</span> — hashes and links valid. (v3 records also signature-valid)`);
  }else{
    setChainStatus(`⚠️ Chain has <b>${broken}</b> broken record(s).`, false);
  }
  return res;
}

// -----------------------
// CERTIFICATE
// -----------------------
function formatPrettyDate(iso){
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { year:"numeric", month:"long", day:"numeric" });
}
function buildVerifyCode(rec){
  return `BRGY|${rec.id}|${rec.hash}`;
}
function renderPrintableCertificate(rec){
  document.getElementById("printArea").style.display = "block";
  lastIssued = rec;

  document.getElementById("pDocTitle").textContent = rec.doctype || "";
  document.getElementById("pName").textContent = rec.name || "";
  document.getElementById("pPurpose").textContent = rec.purpose || "";

  document.getElementById("pIssuedDate").textContent = formatPrettyDate(rec.timestamp);
  document.getElementById("pIssuedPretty").textContent = formatPrettyDate(rec.timestamp);
  document.getElementById("pRecordId").textContent = rec.id;

  document.getElementById("pHash").textContent = rec.hash;
  document.getElementById("pPrevHash").textContent = rec.prevHash;

  document.getElementById("pBarangay2").textContent = document.getElementById("phBarangay").textContent;

  const code = buildVerifyCode(rec);
  document.getElementById("pVerifyCode").textContent = code;

  const qrEl = document.getElementById("printQR");
  qrEl.innerHTML = "";
  new QRCode(qrEl, { text: code, width: 150, height: 150 });
}

// -----------------------
// STATUS: corrected/revoked lookup
// -----------------------
function getLifecycleStatus(issueId){
  // Find all records that reference this issueId
  const refs = ledger.filter(r => (r.refId || "") === issueId);

  // latest by timestamp
  const sorted = refs.slice().sort((a,b)=> (a.timestamp||"").localeCompare(b.timestamp||""));
  const lastRevoke = sorted.filter(r => r.type === "REVOKE").at(-1) || null;
  const lastCorrect = sorted.filter(r => r.type === "CORRECT").at(-1) || null;

  return { lastRevoke, lastCorrect };
}

// -----------------------
// APPEND-ONLY ACTION RECORDS
// -----------------------
async function appendActionRecord(type, refId, note){
  // Staff/Admin only while unlocked (signature required)
  if(!canStaffAction()){
    setActionStatus("Signing is LOCKED. Ask ADMIN to unlock signing first.", false);
    return;
  }

  const target = ledger.find(r => r.id === refId);
  if(!target){
    setActionStatus("Selected record not found.", false);
    return;
  }
  if(target.type !== "ISSUE"){
    setActionStatus("Only ISSUE records can be corrected/revoked.", false);
    return;
  }

  const lifecycle = getLifecycleStatus(refId);
  if(type === "REVOKE" && lifecycle.lastRevoke){
    setActionStatus("This record is already revoked.", false);
    return;
  }

  META = loadMeta();
  if(!META.publicKeyB64){
    setActionStatus("Signing keys not set up. Admin must unlock signing first.", false);
    return;
  }

  const prev = ledger[ledger.length - 1];
  const rec = {
    index: ledger.length,
    type,
    format: "v3",
    id: "BRGY-" + uid(),
    refId,
    name: target.name,
    doctype: target.doctype,
    purpose: note || "",
    timestamp: new Date().toISOString(),
    prevHash: prev.hash,
    pub: META.publicKeyB64,
    sig: ""
  };

  rec.hash = await sha256(buildRecordString(rec));
  rec.sig  = signHashB64(rec.hash, UNLOCKED_SECRET_B64);

  ledger.push(rec);
  saveLedger();
  renderLedger();
  await chainCheck();

  setActionStatus(`<span class="ok">✅ ${type}</span> appended for <span class="mono">${escapeHtml(refId)}</span>.`);
}

// -----------------------
// DAILY SIGNED SUMMARY
// -----------------------
function isoDateLocal(d=new Date()){
  // YYYY-MM-DD in local time
  const yr = d.getFullYear();
  const mo = String(d.getMonth()+1).padStart(2,"0");
  const da = String(d.getDate()).padStart(2,"0");
  return `${yr}-${mo}-${da}`;
}

async function generateDailySummary(){
  if(!isAdmin()){
    setSummaryStatus("Admin only.", false);
    return null;
  }
  if(!SIGNING_UNLOCKED || !UNLOCKED_SECRET_B64){
    setSummaryStatus("Signing is LOCKED. Unlock signing first.", false);
    return null;
  }

  META = loadMeta();
  if(!META.publicKeyB64){
    setSummaryStatus("No signing key found.", false);
    return null;
  }

  const day = isoDateLocal(new Date());
  const head = ledger[ledger.length-1]?.hash || "";

  const issuesToday = ledger.filter(r => r.type === "ISSUE" && (r.timestamp||"").slice(0,10) === day);

  const summaryText =
    `DATE=${day}|TOTAL=${ledger.length}|ISSUED_TODAY=${issuesToday.length}|HEAD=${head}|PUB=${META.publicKeyB64}`;

  const summaryHash = await sha256(summaryText);
  const summarySig  = signHashB64(summaryHash, UNLOCKED_SECRET_B64);

  const obj = {
    kind: "BRGY_DAILY_SUMMARY",
    date: day,
    generatedAt: new Date().toISOString(),
    totalRecords: ledger.length,
    issuedToday: issuesToday.length,
    headHash: head,
    publicKeyB64: META.publicKeyB64,
    summaryText,
    summaryHash,
    signatureB64: summarySig
  };

  lastSummary = obj;

  // render preview A4
  document.getElementById("summaryArea").style.display = "block";
  document.getElementById("sCity").textContent = document.getElementById("phCity").textContent;
  document.getElementById("sBarangay").textContent = document.getElementById("phBarangay").textContent;

  document.getElementById("sDate").textContent = day;
  document.getElementById("sGeneratedAt").textContent = formatPrettyDate(obj.generatedAt);
  document.getElementById("sTotal").textContent = String(obj.totalRecords);
  document.getElementById("sIssuedToday").textContent = String(obj.issuedToday);
  document.getElementById("sHead").textContent = obj.headHash;
  document.getElementById("sHash").textContent = obj.summaryHash;
  document.getElementById("sSig").textContent = obj.signatureB64;

  document.getElementById("exportSummaryBtn").disabled = false;
  document.getElementById("printSummaryBtn").disabled = false;

  setSummaryStatus(`<span class="ok">✅ Summary generated</span> for ${day}.`);

  document.getElementById("summaryArea").scrollIntoView({behavior:"smooth", block:"start"});
  return obj;
}

function downloadJSON(filename, obj){
  const data = JSON.stringify(obj, null, 2);
  const blob = new Blob([data], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// -----------------------
// PRINT HELPERS
// -----------------------
function printCertificate(){
  if(!lastIssued){
    alert("Select or issue a record first to generate a certificate.");
    return;
  }
  document.body.classList.remove("print-summary");
  document.body.classList.add("print-cert");
  window.print();
}
function printSummary(){
  if(!lastSummary){
    alert("Generate a summary first.");
    return;
  }
  document.body.classList.remove("print-cert");
  document.body.classList.add("print-summary");
  window.print();
}
window.addEventListener("afterprint", ()=>{
  document.body.classList.remove("print-cert","print-summary");
});

// -----------------------
// EVENTS
// -----------------------
document.getElementById("loginBtn").addEventListener("click", openLogin);
document.getElementById("logoutBtn").addEventListener("click", ()=>{
  lockSigning();
  clearSession();
  applyRoleUI();
  setVerifyStatus("Logged out.");
});

document.getElementById("loginCancelBtn").addEventListener("click", closeLogin);
document.getElementById("loginOkBtn").addEventListener("click", async ()=>{
  const username = document.getElementById("loginUser").value.trim();
  const password = document.getElementById("loginPass").value;

  if(!username || !password){
    setLoginStatus("Enter username and password.", false);
    return;
  }

  try{
    const created = await ensureAdminOnFirstLogin(username, password);
    if(created){
      setSession({ username: created.username, role: created.role, loginAt: new Date().toISOString() });
      closeLogin();
      applyRoleUI();
      setVerifyStatus("✅ Admin created and logged in.");
      return;
    }

    const u = await verifyLogin(username, password);
    if(!u){
      setLoginStatus("Invalid username or password.", false);
      return;
    }

    setSession({ username: u.username, role: u.role, loginAt: new Date().toISOString() });
    closeLogin();
    applyRoleUI();
    setVerifyStatus("✅ Logged in.");
  }catch(err){
    setLoginStatus(err.message || "Login failed.", false);
  }
});

document.getElementById("changePassBtn").addEventListener("click", ()=>{
  if(!currentUser()) return;
  openPass();
});
document.getElementById("passCancelBtn").addEventListener("click", closePass);
document.getElementById("passOkBtn").addEventListener("click", async ()=>{
  const cur = document.getElementById("curPass").value;
  const np1 = document.getElementById("newPass").value;
  const np2 = document.getElementById("newPass2").value;

  if(!cur || !np1 || !np2){
    setPassStatus("Fill in all fields.", false);
    return;
  }
  if(np1 !== np2){
    setPassStatus("New passwords do not match.", false);
    return;
  }

  try{
    await changeOwnPassword(cur, np1);
    setPassStatus(`<span class="ok">✅ Password updated.</span>`);
    setTimeout(()=>{ closePass(); }, 600);
  }catch(err){
    setPassStatus(err.message || "Failed.", false);
  }
});

// Admin add user
document.getElementById("addUserBtn").addEventListener("click", async ()=>{
  if(!isAdmin()) return;

  const username = prompt("New username:");
  if(!username) return;

  const role = prompt("Role (ADMIN / STAFF / VIEWER):", "STAFF");
  if(!role) return;
  const R = role.toUpperCase();
  if(!["ADMIN","STAFF","VIEWER"].includes(R)){
    alert("Invalid role.");
    return;
  }

  const password = prompt("Temporary password (min 6):");
  if(!password || password.length < 6){
    alert("Password too short.");
    return;
  }

  const users = loadUsers();
  if(users.some(u => u.username.toLowerCase() === username.toLowerCase())){
    alert("Username already exists.");
    return;
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2Hash(password, salt);

  users.push({
    username,
    role: R,
    saltB64: u8ToB64(salt),
    hashB64: u8ToB64(hash),
    createdAt: new Date().toISOString()
  });
  saveUsers(users);
  alert(`User created: ${username} (${R}).`);
});

// Admin reset user password
document.getElementById("resetUserBtn").addEventListener("click", async ()=>{
  if(!isAdmin()) return;

  const username = prompt("Username to reset:");
  if(!username) return;

  const np = prompt("New password (min 6):");
  if(!np) return;

  try{
    await adminResetUserPassword(username, np);
    alert(`Password reset for ${username}.`);
  }catch(err){
    alert(err.message || "Reset failed.");
  }
});

// Unlock/Lock signing
document.getElementById("unlockSignBtn").addEventListener("click", async ()=>{
  const ok = await unlockSigningAdmin();
  if(ok){
    setVerifyStatus("✅ Signing unlocked. STAFF can now Issue/Correct/Revoke while this page remains open.");
    applyRoleUI();
  }
});
document.getElementById("lockSignBtn").addEventListener("click", ()=>{
  lockSigning();
  setVerifyStatus("🔒 Signing locked.");
  applyRoleUI();
});

// Issue
document.getElementById("issueBtn").addEventListener("click", async ()=>{
  if(!canStaffAction()){
    setIssueStatus("Signing is LOCKED. Ask ADMIN to unlock signing first.", false);
    return;
  }

  const name = document.getElementById("name").value.trim();
  const doctype = document.getElementById("doctype").value;
  const purpose = document.getElementById("purpose").value.trim();

  if(!name || !purpose){
    setIssueStatus("Please fill in Name and Purpose/Notes.", false);
    return;
  }

  META = loadMeta();
  if(!META.publicKeyB64){
    setIssueStatus("No signing key found. Admin must unlock signing first.", false);
    return;
  }

  const prev = ledger[ledger.length - 1];

  const record = {
    index: ledger.length,
    type: "ISSUE",
    format: "v3",
    id: "BRGY-" + uid(),
    name,
    doctype,
    purpose,
    timestamp: new Date().toISOString(),
    prevHash: prev.hash,
    pub: META.publicKeyB64,
    sig: "",
    refId: ""
  };

  record.hash = await sha256(buildRecordString(record));
  record.sig  = signHashB64(record.hash, UNLOCKED_SECRET_B64);

  ledger.push(record);
  saveLedger();

  setIssueStatus(`<span class="ok">✅ Saved!</span> Document issued and signed.`);
  renderLedger();
  await chainCheck();

  renderPrintableCertificate(record);
  document.getElementById("printArea").scrollIntoView({behavior:"smooth", block:"start"});
});

// Reset form
document.getElementById("resetBtn").addEventListener("click", ()=>{
  document.getElementById("name").value = "";
  document.getElementById("purpose").value = "";
  setIssueStatus("Ready.");
});

// Verify
document.getElementById("verifyBtn").addEventListener("click", async ()=>{
  const val = document.getElementById("verifyInput").value.trim();
  if(!val){
    setVerifyStatus("Paste a verify code first.", false);
    return;
  }

  const parts = val.split("|");
  if(parts.length !== 3 || parts[0] !== "BRGY"){
    setVerifyStatus("Invalid code format. Expected: BRGY|ID|HASH", false);
    return;
  }

  const id = parts[1];
  const hash = parts[2];

  const found = ledger.find(r => r.id === id);
  if(!found){
    setVerifyStatus("❌ Not found in ledger. This document may be fake or from another ledger.", false);
    return;
  }

  // recompute hash using v2/v3 rules
  const recomputed = await sha256(buildRecordString(found));
  if(found.hash !== recomputed){
    setVerifyStatus("❌ Record exists but was tampered (hash mismatch).", false);
    return;
  }

  // if v3, verify signature; if v2, warn (legacy)
  let sigMsg = "";
  if(found.format === "v3"){
    const pub = found.pub || loadMeta().publicKeyB64;
    if(!found.sig || !pub || !verifyHashSig(found.hash, found.sig, pub)){
      setVerifyStatus("❌ Signature invalid. This record is not officially issued.", false);
      return;
    }
    sigMsg = `<br/>Signature: <span class="ok">VALID</span>`;
  }else{
    sigMsg = `<br/>Signature: <span class="no">LEGACY (unsigned)</span>`;
  }

  if(found.hash !== hash){
    setVerifyStatus("❌ Record exists but code hash does not match (wrong QR/code or altered certificate).", false);
    return;
  }

  // lifecycle status
  let lifecycleMsg = "";
  if(found.type === "ISSUE"){
    const { lastRevoke, lastCorrect } = getLifecycleStatus(found.id);
    if(lastRevoke){
      lifecycleMsg = `<br/>Status: <span class="no">REVOKED</span> (${escapeHtml(lastRevoke.timestamp)})`;
    }else if(lastCorrect){
      lifecycleMsg = `<br/>Status: <span class="ok">CORRECTED</span> (${escapeHtml(lastCorrect.timestamp)})<br/>
      Correction Note: ${escapeHtml(lastCorrect.purpose || "")}`;
    }else{
      lifecycleMsg = `<br/>Status: <span class="ok">VALID</span>`;
    }
  }

  setVerifyStatus(`<span class="ok">✅ VERIFIED</span><br/>
    Name: <b>${escapeHtml(found.name)}</b><br/>
    Document: <b>${escapeHtml(found.doctype)}</b><br/>
    Issued: <span class="mono">${escapeHtml(found.timestamp)}</span>
    ${sigMsg}
    ${lifecycleMsg}
  `);
});

// Click row -> select + show certificate
document.querySelector("#ledgerTable tbody").addEventListener("click", (e)=>{
  const tr = e.target.closest("tr");
  if(!tr) return;

  const i = Number(tr.dataset.index);
  const rec = ledger[i];
  if(!rec || rec.index === 0) return;

  // select
  selectedRecordId = rec.id;
  document.getElementById("selectedId").value = selectedRecordId;

  // show cert preview (only meaningful for ISSUE)
  renderPrintableCertificate(rec);
  document.getElementById("printArea").scrollIntoView({behavior:"smooth", block:"start"});

  setActionStatus(`Selected: <span class="mono">${escapeHtml(selectedRecordId)}</span>`);
});

// Clear selection
document.getElementById("clearSelectBtn").addEventListener("click", ()=>{
  selectedRecordId = null;
  document.getElementById("selectedId").value = "";
  document.getElementById("actionNote").value = "";
  setActionStatus("Select a record first.");
});

// Append correction / revoke
document.getElementById("correctBtn").addEventListener("click", async ()=>{
  if(!selectedRecordId){
    setActionStatus("Select a record first.", false);
    return;
  }
  const note = document.getElementById("actionNote").value.trim();
  await appendActionRecord("CORRECT", selectedRecordId, note);
});
document.getElementById("revokeBtn").addEventListener("click", async ()=>{
  if(!selectedRecordId){
    setActionStatus("Select a record first.", false);
    return;
  }
  const note = document.getElementById("actionNote").value.trim();
  await appendActionRecord("REVOKE", selectedRecordId, note);
});

// Print certificate buttons
document.getElementById("printBtn").addEventListener("click", ()=>{
  if(!lastIssued){
    alert("Select or issue a record first.");
    return;
  }
  document.body.classList.remove("print-summary");
  document.body.classList.add("print-cert");
  window.print();
});
document.getElementById("hideCertBtn").addEventListener("click", ()=>{
  document.getElementById("printArea").style.display = "none";
});

// Tamper demo
document.getElementById("tamperBtn").addEventListener("click", ()=>{
  if(ledger.length <= 1){
    setVerifyStatus("Nothing to tamper (only genesis).", false);
    return;
  }
  ledger[ledger.length - 1].purpose += " [TAMPERED]";
  saveLedger();
  renderLedger();
  setVerifyStatus("⚠️ Last record tampered for demo. Try Verify / Chain Check.", false);
});

// Export / Import / Clear
document.getElementById("exportBtn").addEventListener("click", ()=>{
  const backup = {
    version: "v3_mixed",
    exportedAt: new Date().toISOString(),
    meta: { publicKeyB64: loadMeta().publicKeyB64 || "" },
    ledger
  };
  const ymd = isoDateLocal(new Date());
  downloadJSON(`barangay_ledger_backup_${ymd}.json`, backup);
});

document.getElementById("importBtn").addEventListener("click", ()=>{
  document.getElementById("filePick").click();
});
document.getElementById("filePick").addEventListener("change", (e)=>{
  const file = e.target.files?.[0];
  if(!file) return;

  const reader = new FileReader();
  reader.onload = async ()=>{
    try{
      const obj = JSON.parse(reader.result);

      const importedLedger = Array.isArray(obj) ? obj : obj.ledger;
      if(!Array.isArray(importedLedger) || importedLedger.length < 1) throw new Error("Invalid ledger file.");

      ledger = normalizeLedgerFormat(importedLedger);
      saveLedger();
      renderLedger();
      await chainCheck();
      setVerifyStatus(`<span class="ok">✅ Imported ledger.</span>`);
    }catch(err){
      setVerifyStatus("Import failed: " + (err.message || err), false);
    }
  };
  reader.readAsText(file);
  e.target.value = "";
});

document.getElementById("clearLedgerBtn").addEventListener("click", async ()=>{
  if(!confirm("Clear ledger? This will restore genesis block.")) return;

  localStorage.removeItem(LS_KEY);
  ledger = loadLedger();
  saveLedger();
  renderLedger();
  await chainCheck();
  setVerifyStatus("Ledger cleared. (Genesis restored)");
  setIssueStatus("Ready.");
  document.getElementById("printArea").style.display = "none";
  lastIssued = null;

  // reset selection/summary
  selectedRecordId = null;
  document.getElementById("selectedId").value = "";
  document.getElementById("actionNote").value = "";
  setActionStatus("Select a record first.");

  lastSummary = null;
  document.getElementById("summaryArea").style.display = "none";
  document.getElementById("exportSummaryBtn").disabled = true;
  document.getElementById("printSummaryBtn").disabled = true;
  setSummaryStatus("Admin can generate a signed daily summary (requires signing unlocked).");
});

document.getElementById("checkChainBtn").addEventListener("click", chainCheck);

// Daily summary buttons
document.getElementById("genSummaryBtn").addEventListener("click", generateDailySummary);
document.getElementById("exportSummaryBtn").addEventListener("click", ()=>{
  if(!lastSummary) return;
  downloadJSON(`daily_summary_${lastSummary.date}.json`, lastSummary);
});
document.getElementById("printSummaryBtn").addEventListener("click", ()=>{
  printSummary();
});

// Print mode cleanup
window.addEventListener("afterprint", ()=>{
  document.body.classList.remove("print-cert","print-summary");
});

// -----------------------
// INIT
// -----------------------
renderLedger();
chainCheck();

applyRoleUI();
if(!currentUser()) openLogin();

// Fix action status on load
setActionStatus("Select a record first.");
