"use strict";
const $ = (id) => document.getElementById(id);
async function api(path, params) {
  const r = await fetch(path + "?" + new URLSearchParams(params));
  return r.json();
}
function rows(target, items) {
  target.replaceChildren(...items.map(([k, v, cls]) => {
    const row = document.createElement("div"); row.className = "row";
    const b = document.createElement("b"); b.textContent = k;
    const s = document.createElement("span"); s.textContent = String(v); if (cls) s.className = cls;
    row.append(b, s); return row;
  }));
}
function colorOf(hex) { return "hsl(" + (parseInt(hex.slice(0, 6), 16) % 360) + " 70% 62%)"; }
function blocks(target, list) {
  target.replaceChildren(...list.map((h) => { const d = document.createElement("div"); d.className = "blk"; d.textContent = h.slice(0, 8) + "…"; d.style.background = colorOf(h); d.title = h; return d; }));
}
document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
  document.querySelectorAll("main section").forEach((s) => { s.hidden = s.id !== b.dataset.t; });
}));
let t1, t2;
async function doHash() {
  const j = await api("/api/hash", { text: $("h-text").value, key: $("h-key").value });
  if (j.error) return rows($("h-out"), [["error", j.error, "bad"]]);
  rows($("h-out"), [["SHA-256", j.sha256], ["HMAC-SHA-256", j.hmac], ["SHA-256, 1 bit flipped", j.flipped_sha256], ["bits that changed", j.bits_changed + " of 256 (" + Math.round(j.bits_changed / 2.56) + "%)", "big"]]);
}
async function doEcb() {
  const j = await api("/api/ecb", { text: $("e-text").value });
  if (j.error) return;
  blocks($("e-ecb"), j.ecb); blocks($("e-cbc"), j.cbc);
}
$("h-text").addEventListener("input", () => { clearTimeout(t1); t1 = setTimeout(doHash, 150); });
$("h-key").addEventListener("input", () => { clearTimeout(t1); t1 = setTimeout(doHash, 150); });
$("e-text").addEventListener("input", () => { clearTimeout(t2); t2 = setTimeout(doEcb, 150); });
$("p-run").addEventListener("click", async () => {
  $("p-out").textContent = "running…";
  const j = await api("/api/padding-oracle", { msg: $("p-msg").value });
  if (j.error) return rows($("p-out"), [["error", j.error, "bad"]]);
  rows($("p-out"), [["IV", j.iv], ["ciphertext (" + j.blocks + " blocks)", j.ciphertext], ["recovered without key", j.recovered, "ok big"], ["matches the secret", j.matches, j.matches ? "ok" : "bad"], ["oracle queries", j.queries], ["time", j.ms + " ms"]]);
});
$("l-run").addEventListener("click", async () => {
  const j = await api("/api/length-extension", { msg: $("l-msg").value, append: $("l-app").value });
  if (j.error) return rows($("l-out"), [["error", j.error, "bad"]]);
  if (!j.server_accepts) return rows($("l-out"), [["result", "forgery failed", "bad"]]);
  rows($("l-out"), [["original MAC", j.original_mac], ["forged message", j.forged_message], ["forged MAC", j.forged_mac], ["server accepts forgery", "yes", "bad big"], ["secret length found", j.secret_len + " bytes after " + j.tries + " tries"], ["same attack on HMAC", j.hmac_resists ? "fails: HMAC resists" : "worked", j.hmac_resists ? "ok" : "bad"]]);
});
$("r-run").addEventListener("click", async () => {
  const p = {}; if ($("r-n").value.trim()) p.n = $("r-n").value.trim();
  const j = await api("/api/rsa", p);
  if (j.error) return rows($("r-out"), [["error", j.error, "bad"]]);
  if (!j.factored) return rows($("r-out"), [["n", j.n], ["result", j.note, "ok"]]);
  rows($("r-out"), [["n", j.n], ["p", j.p], ["q", j.q], ["Fermat iterations", j.iterations, "bad big"], ["private exponent d", j.d], ["message → cipher → decrypted", j.demo_message + " → " + j.demo_cipher + " → " + j.decrypted, "ok"], ["time", j.us + " µs"]]);
});
doHash(); doEcb();
