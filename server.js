const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.urlencoded({ extended: true }));

// --- session ---
app.use(session({
  secret: process.env.SESSION_SECRET || "dev_secret_change_me",
  resave: false,
  saveUninitialized: false
}));

// --- mongo ---
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error("❌ MONGODB_URI is missing. Please set it in your .env file");
  process.exit(1);
}

mongoose.connect(mongoUri, { dbName: process.env.MONGODB_DB || "pwmanager" })
  .then(() => console.log("✅ MongoDB connected:", mongoUri))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });

// --- models ---
const User = mongoose.model("User", new mongoose.Schema({
  email: { type: String, unique: true },
  hash: String,
}));

const Entry = mongoose.model("Entry", new mongoose.Schema({
  userId: mongoose.Types.ObjectId,
  site: String,
  link: String,
  uname: String,
  cipher: String, // base64(iv|tag|ciphertext)
}));

// --- crypto helpers ---
const KEY = crypto.createHash("sha256").update(process.env.VAULT_KEY || "dev_vault_key_change_me").digest();
function enc(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}
function dec(b64) {
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString("utf8");
}

// --- auth middleware ---
function authed(req, res, next) {
  if (!req.session.uid) return res.redirect("/");
  next();
}

// --- base template ---
function pageTemplate(body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Password Manager</title></head>
  <body>
    <h2 align="center">Password Manager</h2>
    ${body}
    <p align="center"><small>Demo app. Don’t use in production without hardening.</small></p>
    <script>
      async function copyPw(id){
        const r = await fetch('/pw/'+id);
        if(!r.ok){ alert('Failed'); return;}
        const t = await r.text();
        await navigator.clipboard.writeText(t);
        alert('Password copied.');
      }
      function togglePw(id){
        const f = document.getElementById(id);
        f.type = (f.type === 'password') ? 'text' : 'password';
      }
    </script>
  </body></html>`;
}

// --- home (login/register) ---
const home = (msg = "") => pageTemplate(`
${msg ? `<p align="center">${msg}</p>` : ""}

<!-- Login Form -->
<div id="loginForm">
  <h3 align="center">Login</h3>
  <form method="post" action="/login">
    <table align="center" cellpadding="5">
      <tr>
        <td>Username:</td>
        <td><input name="email" required></td>
      </tr>
      <tr>
        <td>Password:</td>
        <td>
          <input id="loginPass" name="pass" type="password" required>
          <button type="button" onclick="togglePw('loginPass')">Show</button>
        </td>
      </tr>
      <tr>
        <td colspan="2" align="center">
          <button>Login</button> 
          <a href="javascript:void(0)" onclick="showRegister()">Register</a>
        </td>
      </tr>
    </table>
  </form>
</div>

<!-- Register Form (hidden by default) -->
<div id="registerForm" style="display:none;">
  <h3 align="center">Register</h3>
  <form method="post" action="/register">
    <table align="center" cellpadding="5">
      <tr>
        <td>Username:</td>
        <td><input name="email" required></td>
      </tr>
      <tr>
        <td>Password:</td>
        <td>
          <input id="regPass" name="pass" type="password" required>
          <button type="button" onclick="togglePw('regPass')">Show</button>
        </td>
      </tr>
      <tr>
        <td colspan="2" align="center">
          <button>Register</button> 
          <a href="javascript:void(0)" onclick="showLogin()">Back to Login</a>
        </td>
      </tr>
    </table>
  </form>
</div>

<script>
function showRegister(){
  document.getElementById("loginForm").style.display = "none";
  document.getElementById("registerForm").style.display = "block";
}
function showLogin(){
  document.getElementById("registerForm").style.display = "none";
  document.getElementById("loginForm").style.display = "block";
}
</script>
`);

// --- dashboard ---
function dash(user, entries, page = 1, totalPages = 1) {
  const rows = entries.map(e => `<tr class="entry-row">
    <td>${e.site || ""}</td>
    <td><a href="${e.link || "#"}" target="_blank">${e.link || ""}</a></td>
    <td>${e.uname || ""}</td>
    <td>
      <button type="button" onclick="copyPw('${e._id}')">Copy</button>
      <a href="/del/${e._id}" onclick="return confirm('Delete?')">Delete</a>
    </td>
  </tr>`).join("");

  const nav = `
    <div align="center" style="margin-top:20px;">
      ${page > 1 ? `<a href="/vault?page=${page - 1}">Prev</a>` : ""}
      Page ${page} of ${totalPages}
      ${page < totalPages ? `<a href="/vault?page=${page + 1}">Next</a>` : ""}
    </div>
  `;

  return pageTemplate(`
<p align="center">Logged in as <b>${user.email}</b> | <a href="/logout">Logout</a></p>

<h3 align="center">Add Entry</h3>
<form method="post" action="/add">
  <table align="center" cellpadding="5">
    <tr><td>Website:</td><td><input name="site" required></td></tr>
    <tr><td>Link:</td><td><input name="link"></td></tr>
    <tr><td>Username:</td><td><input name="uname" required></td></tr>
    <tr><td>Password:</td><td><input id="addPw" name="pw" type="password" required>
      <button type="button" onclick="togglePw('addPw')">Show</button></td></tr>
    <tr><td colspan="2" align="center"><button>Add</button></td></tr>
  </table>
</form>

<h3 align="center">Your Entries</h3>

<!-- Live Search Box -->
<div align="center" style="margin-bottom:10px;">
  <input type="text" id="searchBox" placeholder="Type to search...">
</div>

<table border="1" cellpadding="6" cellspacing="0" align="center" id="entriesTable">
  <tr><th>Website</th><th>Link</th><th>Username</th><th>Actions</th></tr>
  ${rows || `<tr class="entry-row"><td colspan="4">No entries found</td></tr>`}
</table>

${nav}

<script>
// Live filter without reloading
document.getElementById("searchBox").addEventListener("input", function() {
  const term = this.value.toLowerCase();
  const rows = document.querySelectorAll("#entriesTable .entry-row");
  rows.forEach(row => {
    row.style.display = row.innerText.toLowerCase().includes(term) ? "" : "none";
  });
});
</script>
`);
}



// --- routes ---
app.get("/", (req, res) => {
  if (req.session.uid) return res.redirect("/vault");
  res.send(home());
});

app.post("/register", async (req, res) => {
  try {
    const { email, pass } = req.body;
    if (!email || !pass) return res.send(home("Missing fields"));
    const hash = await bcrypt.hash(pass, 12);
    await User.create({ email, hash });
    res.send(home("Registered! Please login."));
  } catch (e) {
    res.send(home("Registration failed (maybe user exists)."));
  }
});

app.post("/login", async (req, res) => {
  const { email, pass } = req.body;
  const u = await User.findOne({ email });
  if (!u || !(await bcrypt.compare(pass, u.hash))) return res.send(home("Invalid credentials"));
  req.session.uid = u._id.toString();
  res.redirect("/vault");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

app.get("/vault", authed, async (req, res) => {
  const u = await User.findById(req.session.uid);

  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const limit = 20;

  const total = await Entry.countDocuments({ userId: u._id });
  const totalPages = Math.max(Math.ceil(total / limit), 1);

  const entries = await Entry.find({ userId: u._id })
    .sort({ _id: -1 })
    .skip((page - 1) * limit)
    .limit(limit)
    .lean();

  res.send(dash(u, entries, page, totalPages));
});

app.post("/add", authed, async (req, res) => {
  const { site, link, uname, pw } = req.body;
  if (!site || !uname || !pw) return res.redirect("/vault");
  await Entry.create({ userId: req.session.uid, site, link, uname, cipher: enc(pw) });
  res.redirect("/vault");
});

app.get("/del/:id", authed, async (req, res) => {
  await Entry.deleteOne({ _id: req.params.id, userId: req.session.uid });
  res.redirect("/vault");
});

app.get("/pw/:id", authed, async (req, res) => {
  const e = await Entry.findOne({ _id: req.params.id, userId: req.session.uid }).lean();
  if (!e) return res.status(404).send("Not found");
  try {
    res.type("text").send(dec(e.cipher));
  } catch (err) {
    res.status(500).send("Decrypt error");
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running: http://localhost:${PORT}`));
