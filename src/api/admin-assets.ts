/**
 * Client-side CSS/JS for the admin panel, injected inline into the rendered
 * pages. Ported from vaultwarden's admin.css + admin.js + admin_settings.js
 * (theme switcher, `_post` helper, settings save/reset, SMTP test, and the
 * user/organization mutation handlers), adapted to Vaultur's endpoints.
 */

export const ADMIN_CSS = `
body { padding-top: 75px; }
@media (min-width: 1600px) { .container-xxl { max-width: 1520px; } }
@media (min-width: 1800px) { .container-xxl { max-width: 1720px; } }
.vaultur-icon { height: 30px; width: auto; margin: -4px 6px 0 0; }
.alert-row {
  --bs-alert-border: 1px solid var(--bs-alert-border-color);
  color: var(--bs-alert-color);
  background-color: var(--bs-alert-bg);
  border: var(--bs-alert-border);
}
.is-overridden-true {
  --bs-alert-color: #664d03;
  --bs-alert-bg: #fff3cd;
  --bs-alert-border-color: #ffecb5;
}
#config-block ::placeholder { color: #adb5bd; }
#users-table .vw-account-details { min-width: 250px; }
#users-table .vw-created-at, #users-table .vw-last-active { min-width: 95px; }
#users-table .vw-actions, #orgs-table .vw-actions { min-width: 170px; }
.theme-icon, .theme-icon-active { display: inline-flex; flex: 0 0 1.75em; justify-content: center; }
.theme-icon svg, .theme-icon-active svg { width: 1.25em; height: 1.25em; display: block; }
.cf-badge { font-weight: 600; }
`

export const ADMIN_JS = `
"use strict";
function getBaseUrl() {
  const pathname = window.location.pathname;
  const adminPos = pathname.indexOf("/admin");
  const newPathname = pathname.substring(0, adminPos != -1 ? adminPos : pathname.length);
  return window.location.origin + newPathname;
}
const BASE_URL = getBaseUrl();

function reload() { window.location = window.location.href; }
function msg(text, reload_page) {
  if (reload_page === undefined) reload_page = true;
  if (text) alert(text);
  if (reload_page) reload();
}
function _fetch(method, url, successMsg, errMsg, body, reload_page) {
  if (reload_page === undefined) reload_page = true;
  let status, statusText;
  return fetch(url, {
    method: method, body: body, mode: "same-origin", credentials: "same-origin",
    headers: { "Content-Type": "application/json" }
  }).then(resp => {
    if (resp.ok) { msg(successMsg, reload_page); return Promise.reject({ error: false }); }
    status = resp.status; statusText = resp.statusText; return resp.text();
  }).then(respText => {
    try {
      const j = JSON.parse(respText);
      if (j.errorModel && j.errorModel.message) return j.errorModel.message;
      if (j.message) return j.message;
      return Promise.reject({ body: status + " - " + statusText, error: true });
    } catch (e) { return Promise.reject({ body: status + " - " + statusText, error: true }); }
  }).then(apiMsg => { msg(errMsg + "\\n" + apiMsg, reload_page); })
    .catch(e => { if (e.error === false) return true; else msg(errMsg + "\\n" + (e.body||""), reload_page); });
}
function _post(url, s, e, body, reload_page) { return _fetch("POST", url, s, e, body, reload_page); }

// ---- Bootstrap theme switcher ----
const getStoredTheme = () => localStorage.getItem("theme");
const setStoredTheme = t => localStorage.setItem("theme", t);
const getPreferredTheme = () => getStoredTheme() || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
const setTheme = t => {
  if (t === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches) document.documentElement.setAttribute("data-bs-theme", "dark");
  else document.documentElement.setAttribute("data-bs-theme", t);
};
setTheme(getPreferredTheme());
const showActiveTheme = (theme, focus) => {
  const sw = document.querySelector("#bd-theme"); if (!sw) return;
  const activeIcon = document.querySelector(".theme-icon-active use");
  const btn = document.querySelector('[data-bs-theme-value="' + theme + '"]'); if (!btn) return;
  const use = btn.querySelector("[data-theme-icon-use]");
  const href = use ? use.getAttribute("href") : null;
  document.querySelectorAll("[data-bs-theme-value]").forEach(el => { el.classList.remove("active"); el.setAttribute("aria-pressed","false"); });
  btn.classList.add("active"); btn.setAttribute("aria-pressed","true");
  if (href && activeIcon) activeIcon.setAttribute("href", href);
  if (focus) sw.focus();
};
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  const s = getStoredTheme(); if (s !== "light" && s !== "dark") setTheme(getPreferredTheme());
});

// ---- Settings ----
function getFormData() {
  const data = {};
  document.querySelectorAll(".conf-checkbox").forEach(e => { data[e.name] = e.checked; });
  document.querySelectorAll(".conf-number").forEach(e => { data[e.name] = e.value ? +e.value : null; });
  document.querySelectorAll(".conf-text, .conf-password").forEach(e => { data[e.name] = e.value || null; });
  return data;
}
function saveConfig(event) {
  event.preventDefault();
  _post(BASE_URL + "/admin/config", "Config saved correctly", "Error saving config", JSON.stringify(getFormData()));
}
function deleteConf(event) {
  event.preventDefault();
  const input = prompt("This restores env defaults and removes all admin overrides. Type 'DELETE' to proceed:");
  if (input === "DELETE") _post(BASE_URL + "/admin/config/delete", "Config reset to defaults", "Error resetting config");
  else if (input !== null) alert("Wrong input, please try again");
}
function smtpTest(event) {
  event.preventDefault(); event.stopPropagation();
  if (formHasChanges(document.getElementById("config-form"))) {
    alert("Config has been changed but not saved.\\nPlease save first before sending a test email."); return false;
  }
  const el = document.getElementById("smtp-test-email");
  if (!el.value.match(/\\S+@\\S+/i)) { el.parentElement.classList.add("was-validated"); return false; }
  _post(BASE_URL + "/admin/test/smtp", "Test email sent", "Error sending test email", JSON.stringify({ email: el.value }), false);
}
function initChangeDetection(form) {
  if (!form) return;
  Array.from(form).forEach(el => { if (el.id !== "smtp-test-email") el.dataset.origValue = el.value; });
}
function formHasChanges(form) {
  return form && Array.from(form).some(el => "origValue" in el.dataset && el.dataset.origValue !== el.value);
}
function toggleVis(event) {
  event.preventDefault();
  const elem = document.getElementById(event.currentTarget.dataset.vwPwToggle);
  elem.setAttribute("type", elem.getAttribute("type") === "text" ? "password" : "text");
}
function colorRiskSettings() {
  document.querySelectorAll(".col-form-label").forEach(el => {
    if (el.textContent.toLowerCase().includes("risk")) el.parentElement.className += " alert-danger";
  });
}

// ---- Users / Orgs mutations ----
function userAction(uuid, email, action, confirmMsg) {
  if (confirmMsg && !confirm(confirmMsg.replace("%s", email))) return;
  _post(BASE_URL + "/admin/users/" + uuid + "/" + action, "", "Action failed");
}
function inviteUser(event) {
  event.preventDefault();
  const email = document.getElementById("invite-email").value.trim();
  if (!email) return;
  _post(BASE_URL + "/admin/invite", "Invited " + email, "Invite failed", JSON.stringify({ email: email }));
}
function deleteOrg(uuid, name) {
  if (!confirm("Delete organization '" + name + "' and all its data? This cannot be undone.")) return;
  _post(BASE_URL + "/admin/organizations/" + uuid + "/delete", "", "Delete failed");
}

document.addEventListener("DOMContentLoaded", () => {
  showActiveTheme(getPreferredTheme());
  document.querySelectorAll("[data-bs-theme-value]").forEach(t => t.addEventListener("click", () => {
    const theme = t.getAttribute("data-bs-theme-value");
    setStoredTheme(theme); setTheme(theme); showActiveTheme(theme, true);
  }));
  // Active nav item
  const path = window.location.pathname;
  document.querySelectorAll('.navbar-nav .nav-item a').forEach(a => {
    if (a.getAttribute("href") === path) { a.classList.add("active"); a.setAttribute("aria-current","page"); }
  });

  const form = document.getElementById("config-form");
  if (form) {
    initChangeDetection(form);
    form.addEventListener("keypress", e => { if (e.key === "Enter" && e.target.id !== "smtp-test-email") e.preventDefault(); });
    form.addEventListener("submit", saveConfig);
    colorRiskSettings();
    document.querySelectorAll("button[data-vw-pw-toggle]").forEach(b => b.addEventListener("click", toggleVis));
    const del = document.getElementById("deleteConf"); if (del) del.addEventListener("click", deleteConf);
    const st = document.getElementById("smtpTest"); if (st) st.addEventListener("click", smtpTest);
    const ste = document.getElementById("smtp-test-email");
    if (ste) ste.addEventListener("keypress", e => { if (e.key === "Enter") smtpTest(e); });
  }

  // Delegated actions for users/orgs tables
  document.addEventListener("click", e => {
    const btn = e.target.closest("[data-act]"); if (!btn) return;
    const act = btn.getAttribute("data-act");
    if (act === "invite") return; // handled by form submit
    if (act === "delete-org") { deleteOrg(btn.dataset.uuid, btn.dataset.name); return; }
    const email = btn.dataset.email, uuid = btn.dataset.uuid;
    const confirms = {
      "delete": "Delete user %s and all their data? This cannot be undone.",
      "disable": "Disable user %s? They will be logged out.",
      "deauth": "Log %s out of all devices?",
      "remove-2fa": "Remove all 2FA methods for %s?"
    };
    userAction(uuid, email, act, confirms[act]);
  });
  const inviteForm = document.getElementById("invite-form");
  if (inviteForm) inviteForm.addEventListener("submit", inviteUser);
});
`
