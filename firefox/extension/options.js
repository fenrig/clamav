/* global browser */

const checkbox = document.getElementById("automaticScanning");
const uploadCheckbox = document.getElementById("uploadScanning");
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

browser.storage.local.get({ automaticScanning: true, uploadScanning: true }).then((settings) => {
  checkbox.checked = settings.automaticScanning !== false;
  uploadCheckbox.checked = settings.uploadScanning !== false;
}).catch(() => {
  checkbox.checked = true;
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
