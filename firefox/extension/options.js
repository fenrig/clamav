/* global browser */

const checkbox = document.getElementById("automaticScanning");
const status = document.getElementById("status");

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
  showStatus("Unable to read settings.");
});

checkbox.addEventListener("change", () => {
  browser.storage.local.set({ automaticScanning: checkbox.checked })
    .then(() => showStatus("Settings saved."))
    .catch(() => showStatus("Unable to save settings."));
});
