/* global messenger */

const defaults = { autoScan: true };
const cacheDefaults = { maxEntries: 1000, maxAgeDays: 180 };
let accounts = {};

function localizePage() {
  const token = /__MSG_([A-Za-z0-9_]+)__/g;
  const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);
  for (const node of textNodes) {
    node.nodeValue = node.nodeValue.replace(token, (_, key) => messenger.i18n.getMessage(key) || key);
  }
  for (const element of document.querySelectorAll("*")) {
    for (const attribute of element.attributes) {
      token.lastIndex = 0;
      if (token.test(attribute.value)) {
        token.lastIndex = 0;
        attribute.value = attribute.value.replace(token, (_, key) => messenger.i18n.getMessage(key) || key);
      }
    }
  }
}

localizePage();

async function load() {
  const listed = await messenger.accounts.list();
  const stored = await messenger.storage.local.get(["accounts", "cache", "diagnosticLogging", "scanDownloads", "scanOutgoing"]);
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
  document.getElementById("scanDownloads").checked = stored.scanDownloads !== false;
  document.getElementById("scanOutgoing").checked = stored.scanOutgoing !== false;
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
    scanDownloads: document.getElementById("scanDownloads").checked,
    scanOutgoing: document.getElementById("scanOutgoing").checked,
    cache: {
      ...(old.cache || {}),
      maxEntries: Math.max(0, Number(document.getElementById("maxEntries").value) || 0),
      maxAgeDays: Math.max(0, Number(document.getElementById("maxAgeDays").value) || 0)
    }
  });
  document.getElementById("status").textContent = messenger.i18n.getMessage("saved") || "Saved";
}

document.getElementById("save").addEventListener("click", save);
load();
