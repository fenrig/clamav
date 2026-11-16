/* global browser */

const checkbox = document.getElementById("automaticScanning");
const status = document.getElementById("status");

function message(key) {
  return browser.i18n.getMessage(key) || key;
}

function showStatus(message) {
  status.textContent = message;
  window.setTimeout(() => {
    if (status.textContent === message) status.textContent = "";
  }, 1800);
}

browser.storage.local.get({ automaticScanning: true }).then((settings) => {
  checkbox.checked = settings.automaticScanning !== false;
}).catch(() => {
  checkbox.checked = true;
  showStatus(message("settingsReadError"));
});

checkbox.addEventListener("change", () => {
  browser.storage.local.set({ automaticScanning: checkbox.checked })
    .then(() => showStatus(message("settingsSaved")))
    .catch(() => showStatus(message("settingsSaveError")));
});
