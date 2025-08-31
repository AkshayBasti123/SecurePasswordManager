let currentUser = "";

async function register() {
  const user = document.getElementById("user").value;
  const pass = document.getElementById("pass").value;

  const res = await fetch("http://localhost:8080/register", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({user, pass})
  });

  document.getElementById("message").innerText = await res.text();
}

async function login() {
  const user = document.getElementById("user").value;
  const pass = document.getElementById("pass").value;

  const res = await fetch("http://localhost:8080/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({user, pass})
  });

  if (res.ok) {
    currentUser = user;
    document.getElementById("authCard").classList.add("hidden");
    document.getElementById("vaultCard").classList.remove("hidden");
    document.getElementById("welcomeUser").innerText = user;
    loadVault();
  } else {
    document.getElementById("message").innerText = await res.text();
  }
}

async function savePassword() {
  const entry = document.getElementById("entry").value;

  await fetch("http://localhost:8080/save", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({user: currentUser, entry})
  });

  document.getElementById("entry").value = "";
  loadVault();
}

async function loadVault() {
  const res = await fetch(`http://localhost:8080/vault/${currentUser}`);
  const passwords = await res.json();

  const list = document.getElementById("vaultList");
  list.innerHTML = "";
  passwords.forEach(p => {
    let li = document.createElement("li");
    li.innerText = p;
    list.appendChild(li);
  });
}
