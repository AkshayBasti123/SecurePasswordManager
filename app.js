let token = "";
let currentUser = "";
let entries = []; // local cache for rendering

// ---------- Tabs & Theme ----------
function showTab(which) {
  const loginTab = document.getElementById("loginTab");
  const registerTab = document.getElementById("registerTab");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  if (which === "login") {
    loginTab.classList.add("active");
    registerTab.classList.remove("active");
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
  } else {
    registerTab.classList.add("active");
    loginTab.classList.remove("active");
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
  }
}

function toggleTheme() {
  // Simple toggle: body class 'light' is controlled via <html> root pseudo (handled in CSS)
  document.documentElement.classList.toggle("light");
}

// ---------- Strength Meter ----------
function updateStrength(inputId, barId) {
  const val = document.getElementById(inputId).value;
  const bar = document.getElementById(barId);
  const score = passwordScore(val);
  bar.style.width = Math.min(score, 100) + "%";
}

function passwordScore(pw) {
  if (!pw) return 0;
  let s = 0;
  const sets = [
    /[a-z]/.test(pw),
    /[A-Z]/.test(pw),
    /[0-9]/.test(pw),
    /[^A-Za-z0-9]/.test(pw)
  ].filter(Boolean).length;
  s += Math.min(40, pw.length * 3);  // length
  s += sets * 15;                    // variety
  if (/([A-Za-z0-9])\1{2,}/.test(pw)) s -= 10; // repeated chars
  return Math.max(0, Math.min(100, s));
}

// ---------- Auth ----------
async function registerUser() {
  const user = document.getElementById("regUser").value.trim();
  const pass = document.getElementById("regPass").value;
  const r = await fetch("http://localhost:8080/register", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({user, pass})
  });
  const text = await r.text();
  document.getElementById("regMsg").textContent = tryMsg(text);
}

async function login() {
  const user = document.getElementById("loginUser").value.trim();
  const pass = document.getElementById("loginPass").value;
  const r = await fetch("http://localhost:8080/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({user, pass})
  });
  if (!r.ok) {
    document.getElementById("authMsg").textContent = await r.text();
    return;
  }
  const data = await r.json();
  token = data.token;
  currentUser = data.user;
  document.getElementById("welcomeUser").textContent = currentUser;

  // swap cards with smoothness
  document.getElementById("authCard").classList.add("hidden");
  document.getElementById("vaultCard").classList.remove("hidden");

  await loadVault();
}

async function logout() {
  try {
    await fetch("http://localhost:8080/logout", {
      method: "POST",
      headers: {"Authorization":"Bearer " + token}
    });
  } catch {}
  token = ""; currentUser = ""; entries = [];
  document.getElementById("vaultList").innerHTML = "";
  document.getElementById("vaultCard").classList.add("hidden");
  document.getElementById("authCard").classList.remove("hidden");
}

// ---------- Vault ----------
async function addEntry() {
  const site = document.getElementById("site").value.trim();
  const account = document.getElementById("account").value.trim();
  const secret = document.getElementById("secret").value;
  if (!site || !account || !secret) return;

  const r = await fetch("http://localhost:8080/passwords", {
    method: "POST",
    headers: {"Content-Type":"application/json", "Authorization":"Bearer " + token},
    body: JSON.stringify({site, account, secret})
  });
  if (!r.ok) return alert("Failed to add entry");
  document.getElementById("site").value="";
  document.getElementById("account").value="";
  document.getElementById("secret").value="";
  await loadVault();
}

async function loadVault() {
  const r = await fetch("http://localhost:8080/passwords", {
    headers: {"Authorization":"Bearer " + token}
  });
  if (!r.ok) return;
  entries = await r.json();
  renderVault();
}

async function deleteEntry(id) {
  const r = await fetch(`http://localhost:8080/passwords/${id}`, {
    method: "DELETE",
    headers: {"Authorization":"Bearer " + token}
  });
  if (r.ok) {
    entries = entries.filter(e => e.id !== id);
    renderVault();
  } else {
    alert("Delete failed");
  }
}

function renderVault() {
  const q = document.getElementById("search").value.toLowerCase().trim();
  const list = document.getElementById("vaultList");
  list.innerHTML = "";

  entries
    .filter(e =>
      !q || e.site.toLowerCase().includes(q) || e.account.toLowerCase().includes(q))
    .forEach(e => {
      const li = document.createElement("li");
      li.innerHTML = `
        <span><strong>${escapeHtml(e.site)}</strong></span>
        <span>${escapeHtml(e.account)}</span>
        <span class="badge">••• ${mask(e.secret)}</span>
        <button onclick="copyValue('${encodeURIComponent(e.secret)}')">Copy</button>
        <button class="danger" onclick="deleteEntry('${e.id}')">Delete</button>
      `;
      list.appendChild(li);
    });
}

// ---------- Utilities ----------
function copyValue(v) {
  const text = decodeURIComponent(v);
  navigator.clipboard.writeText(text);
}

function copyText(id) {
  const el = document.getElementById(id);
  if (el && el.value) navigator.clipboard.writeText(el.value);
}

function mask(s) {
  if (!s) return "";
  return s.length <= 4 ? "****" : "*".repeat(Math.max(0, s.length-4)) + s.slice(-4);
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function tryMsg(text) {
  try { const o = JSON.parse(text); return o.message || text; } catch { return text; }
}

// Password generator
function generatePassword() {
  const len = Math.max(8, Math.min(64, Number(document.getElementById("genLen").value) || 16));
  const sets = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "!@#$%^&*()_+-=[]{};:,.?/|~"
  ];
  let all = sets.join("");
  let pw = "";
  // ensure at least one from each set
  for (let i=0;i<sets.length;i++) pw += sets[i][Math.floor(Math.random()*sets[i].length)];
  for (let i=pw.length;i<len;i++) pw += all[Math.floor(Math.random()*all.length)];
  // shuffle
  pw = pw.split("").sort(()=>Math.random()-0.5).join("");
  document.getElementById("genOut").value = pw;
}
