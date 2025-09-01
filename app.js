// app.js - frontend logic that talks to the Java server at http://localhost:8080
let token = "";
let currentUser = "";
let entries = [];

function showTab(which) {
  const loginTab = document.getElementById("loginTab");
  const registerTab = document.getElementById("registerTab");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  if (which === "login") {
    loginTab.classList.add("active"); registerTab.classList.remove("active");
    loginForm.classList.remove("hidden"); registerForm.classList.add("hidden");
  } else {
    registerTab.classList.add("active"); loginTab.classList.remove("active");
    registerForm.classList.remove("hidden"); loginForm.classList.add("hidden");
  }
}

function toggleTheme() { document.documentElement.classList.toggle("light"); }

function updateStrength(inputId, barId) {
  const val = document.getElementById(inputId).value;
  const bar = document.getElementById(barId);
  const score = passwordScore(val);
  bar.style.width = Math.min(score,100) + "%";
}
function passwordScore(pw) {
  if (!pw) return 0;
  let s=0;
  const sets = [ /[a-z]/.test(pw), /[A-Z]/.test(pw), /[0-9]/.test(pw), /[^A-Za-z0-9]/.test(pw) ].filter(Boolean).length;
  s += Math.min(40, pw.length*3);
  s += sets*15;
  if (/([A-Za-z0-9])\1{2,}/.test(pw)) s-=10;
  return Math.max(0, Math.min(100, s));
}

async function registerUser(){
  const user = document.getElementById("regUser").value.trim();
  const pass = document.getElementById("regPass").value;
  try {
    const res = await fetch("http://localhost:8080/register", {
      method:"POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({user, pass})
    });
    const text = await res.text();
    document.getElementById("regMsg").textContent = text ? tryMsg(text) : "OK";
  } catch (e) {
    document.getElementById("regMsg").textContent = "Network error";
  }
}

async function login(){
  const user = document.getElementById("loginUser").value.trim();
  const pass = document.getElementById("loginPass").value;
  try {
    const res = await fetch("http://localhost:8080/login", {
      method:"POST", headers: {"Content-Type":"application/json"},
      body: JSON.stringify({user, pass})
    });
    if (!res.ok) {
      const txt = await res.text();
      document.getElementById("authMsg").textContent = tryMsg(txt);
      return;
    }
    const obj = await res.json();
    token = obj.token; currentUser = obj.user;
    document.getElementById("welcomeUser").textContent = currentUser;
    document.getElementById("authCard").classList.add("hidden");
    document.getElementById("vaultCard").classList.remove("hidden");
    await loadVault();
  } catch (e) {
    document.getElementById("authMsg").textContent = "Network error";
  }
}

async function logout(){
  try {
    await fetch("http://localhost:8080/logout", { method:"POST", headers: { "Authorization":"Bearer "+token }});
  } catch {}
  token=""; currentUser=""; entries=[];
  document.getElementById("vaultCard").classList.add("hidden");
  document.getElementById("authCard").classList.remove("hidden");
}

async function addEntry(){
  const site = document.getElementById("site").value.trim();
  const account = document.getElementById("account").value.trim();
  const secret = document.getElementById("secret").value;
  if (!site || !account || !secret) return alert("site/account/secret required");
  const res = await fetch("http://localhost:8080/passwords", {
    method:"POST",
    headers: {"Content-Type":"application/json", "Authorization":"Bearer "+token},
    body: JSON.stringify({site, account, secret})
  });
  if (!res.ok) return alert("failed to add");
  document.getElementById("site").value=""; document.getElementById("account").value=""; document.getElementById("secret").value="";
  await loadVault();
}

async function loadVault(){
  const res = await fetch("http://localhost:8080/passwords", {
    headers: {"Authorization":"Bearer "+token}
  });
  if (!res.ok) return alert("failed to load vault");
  entries = await res.json();
  renderVault();
}

async function deleteEntry(id){
  const res = await fetch("http://localhost:8080/passwords/" + id, {
    method:"DELETE", headers: {"Authorization":"Bearer "+token}
  });
  if (!res.ok) return alert("delete failed");
  entries = entries.filter(e => e.id !== id);
  renderVault();
}

function renderVault(){
  const q = document.getElementById("search").value.toLowerCase().trim();
  const list = document.getElementById("vaultList");
  list.innerHTML = "";
  entries.filter(e => !q || e.site.toLowerCase().includes(q) || e.account.toLowerCase().includes(q))
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

function copyValue(v){ navigator.clipboard.writeText(decodeURIComponent(v)); }
function copyText(id){ const el=document.getElementById(id); if (el && el.value) navigator.clipboard.writeText(el.value); }
function mask(s){ if (!s) return ""; return s.length<=4 ? "****" : "*".repeat(Math.max(0,s.length-4)) + s.slice(-4); }
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function tryMsg(text){ try { return JSON.parse(text).message || text } catch { return text } }

// password generator
function generatePassword(){
  const len = Math.max(8, Math.min(64, Number(document.getElementById("genLen").value) || 16));
  const sets = ["abcdefghijklmnopqrstuvwxyz","ABCDEFGHIJKLMNOPQRSTUVWXYZ","0123456789","!@#$%^&*()_+-=[]{};:,.?/|~"];
  let pw = "";
  for (let i=0;i<sets.length;i++) pw += sets[i][Math.floor(Math.random()*sets[i].length)];
  const all = sets.join("");
  for (let i=pw.length;i<len;i++) pw += all[Math.floor(Math.random()*all.length)];
  pw = pw.split("").sort(()=>Math.random()-0.5).join("");
  document.getElementById("genOut").value = pw;
}
