/* global browser */

const checkbox = document.getElementById("automaticScanning");
const uploadCheckbox = document.getElementById("uploadScanning");
const cleanCheckbox = document.getElementById("cleanNotifications");
const workersInput = document.getElementById("nativeWorkers");
const status = document.getElementById("status");

function maximumNativeWorkers() {
  const processors = Math.max(1, Number(navigator.hardwareConcurrency) || 1);
  return Math.max(1, Math.floor(processors / 2));
}

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

workersInput.max = maximumNativeWorkers();
browser.storage.local.get({ automaticScanning: true, uploadScanning: true, cleanNotifications: false, nativeWorkers: 2 }).then((settings) => {
  checkbox.checked = settings.automaticScanning !== false;
  uploadCheckbox.checked = settings.uploadScanning !== false;
  cleanCheckbox.checked = settings.cleanNotifications === true;
  workersInput.value = Math.max(1, Math.min(Number(workersInput.max), Number(settings.nativeWorkers) || 2));
}).catch(() => {
  checkbox.checked = true;
  cleanCheckbox.checked = false;
  workersInput.value = Math.min(2, Number(workersInput.max));
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

workersInput.addEventListener("change", () => {
  const value = Math.max(1, Math.min(maximumNativeWorkers(), Number(workersInput.value) || 2));
  workersInput.value = value;
  browser.storage.local.set({ nativeWorkers: value })
    .then(() => showStatus(message("settingsSaved")))
    .catch(() => showStatus(message("settingsSaveError")));
});
