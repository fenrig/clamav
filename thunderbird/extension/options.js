/* global messenger */

const defaults = { autoScan: true };
const cacheDefaults = { maxEntries: 1000, maxAgeDays: 180 };
let accounts = {};

async function load() {
  const listed = await messenger.accounts.list();
  const stored = await messenger.storage.local.get(["accounts", "cache", "diagnosticLogging"]);
  accounts = stored.accounts || {};
  const select = document.getElementById("account");
  for (const account of listed.filter(item => item.id)) {
    const option = document.createElement("option");
    option.value = account.id;
    option.textContent = account.name || account.email || account.id;
    select.appendChild(option);
  }
  const cache = { ...cacheDefaults, ...(stored.cache || {}) };
  document.getElementById("maxEntries").value = cache.maxEntries;
  document.getElementById("maxAgeDays").value = cache.maxAgeDays;
  document.getElementById("diagnosticLogging").checked = stored.diagnosticLogging === true;
  select.addEventListener("change", showAccount);
  showAccount();
}

function showAccount() {
  const value = { ...defaults, ...(accounts[document.getElementById("account").value] || {}) };
  document.getElementById("autoScan").checked = value.autoScan;
}

async function save() {
  accounts[document.getElementById("account").value] = {
    autoScan: document.getElementById("autoScan").checked
  };
  const old = await messenger.storage.local.get("cache");
  await messenger.storage.local.set({
    accounts,
    diagnosticLogging: document.getElementById("diagnosticLogging").checked,
    cache: {
      ...(old.cache || {}),
      maxEntries: Math.max(0, Number(document.getElementById("maxEntries").value) || 0),
      maxAgeDays: Math.max(0, Number(document.getElementById("maxAgeDays").value) || 0)
    }
  });
  document.getElementById("status").textContent = "Saved";
}

document.getElementById("save").addEventListener("click", save);
load();
