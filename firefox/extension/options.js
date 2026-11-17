/* global browser */

const checkbox = document.getElementById("automaticScanning");
const uploadCheckbox = document.getElementById("uploadScanning");
const cleanCheckbox = document.getElementById("cleanNotifications");
const status = document.getElementById("status");

function message(key) {
  return browser.i18n.getMessage(key) || key;
}

function localizePage() {
  const token = /__MSG_([A-Za-z0-9_]+)__/g;
  const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
  const textNodes = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode);
  for (const node of textNodes) {
    node.nodeValue = node.nodeValue.replace(token, (_, key) => message(key));
  }
  for (const element of document.querySelectorAll("*")) {
    for (const attribute of element.attributes) {
      token.lastIndex = 0;
      if (token.test(attribute.value)) {
        token.lastIndex = 0;
        attribute.value = attribute.value.replace(token, (_, key) => message(key));
      }
    }
  }
}

localizePage();

function showStatus(message) {
  status.textContent = message;
  window.setTimeout(() => {
    if (status.textContent === message) status.textContent = "";
  }, 1800);
}

browser.storage.local.get({ automaticScanning: true, uploadScanning: true, cleanNotifications: false }).then((settings) => {
  checkbox.checked = settings.automaticScanning !== false;
  uploadCheckbox.checked = settings.uploadScanning !== false;
  cleanCheckbox.checked = settings.cleanNotifications === true;
}).catch(() => {
  checkbox.checked = true;
  cleanCheckbox.checked = false;
  showStatus(message("settingsReadError"));
});

checkbox.addEventListener("change", () => {
  browser.storage.local.set({ automaticScanning: checkbox.checked })
    .then(() => showStatus(message("settingsSaved")))
    .catch(() => showStatus(message("settingsSaveError")));
});

uploadCheckbox.addEventListener("change", () => {
  browser.storage.local.set({ uploadScanning: uploadCheckbox.checked })
    .then(() => showStatus(message("settingsSaved")))
    .catch(() => showStatus(message("settingsSaveError")));
});

cleanCheckbox.addEventListener("change", () => {
  browser.storage.local.set({ cleanNotifications: cleanCheckbox.checked })
    .then(() => showStatus(message("settingsSaved")))
    .catch(() => showStatus(message("settingsSaveError")));
});
