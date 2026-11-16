/* global browser */

const NATIVE_HOST = "org.clamav.thunderbird";
const message = (key, substitutions) => browser.i18n.getMessage(key, substitutions) || key;
let nativePort = null;
let nativeCurrent = null;
const nativeQueue = [];
const scannedDownloads = new Set();
const uploadOverrides = new Map();
const UPLOAD_OVERRIDE_TTL_MS = 15 * 60 * 1000;
let automaticScanning = true;
let uploadScanning = true;

const automaticScanningReady = browser.storage.local.get({ automaticScanning: true, uploadScanning: true }).then((settings) => {
  automaticScanning = settings.automaticScanning !== false;
  uploadScanning = settings.uploadScanning !== false;
}).catch(() => {
  automaticScanning = true;
  uploadScanning = true;
});

browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.automaticScanning)
    automaticScanning = changes.automaticScanning.newValue !== false;
  if (areaName === "local" && changes.uploadScanning)
    uploadScanning = changes.uploadScanning.newValue !== false;
});

function pumpNativeQueue() {
  if (nativeCurrent || nativeQueue.length === 0) return;
  if (!nativePort) {
    try {
      nativePort = browser.runtime.connectNative(NATIVE_HOST);
    } catch (error) {
      nativeQueue.shift().reject(error);
      pumpNativeQueue();
      return;
    }
    nativePort.onMessage.addListener((message) => {
      if (!nativeCurrent) return;
      const request = nativeCurrent;
      nativeCurrent = null;
      request.resolve(message);
      pumpNativeQueue();
    });
    nativePort.onDisconnect.addListener(() => {
      const error = browser.runtime.lastError?.message || "ClamAV native host disconnected";
      const request = nativeCurrent;
      nativeCurrent = null;
      nativePort = null;
      if (request) request.reject(new Error(error));
      pumpNativeQueue();
    });
  }
  nativeCurrent = nativeQueue.shift();
  try {
      nativePort.postMessage({ path: nativeCurrent.path, quarantine: nativeCurrent.quarantine, component: "firefox" });
  } catch (error) {
    const request = nativeCurrent;
    nativeCurrent = null;
    nativePort = null;
    request.reject(error);
    pumpNativeQueue();
  }
}

function scanWithNativeHost(path, quarantine = false) {
  return new Promise((resolve, reject) => {
    nativeQueue.push({ path, quarantine, resolve, reject });
    pumpNativeQueue();
  });
}

async function openQuarantine() {
  try {
    await browser.runtime.sendNativeMessage(NATIVE_HOST, { command: "open_quarantine" });
  } catch (error) {
    console.error("ClamAV: unable to open quarantine manager", error);
  }
}

browser.notifications.onClicked.addListener((notificationId) => {
  if (notificationId.startsWith("clamav-quarantine-")) {
    openQuarantine();
  }
});

function uploadFilePaths(details) {
  return (details.requestBody?.raw || [])
    .map(part => part.file)
    .filter(path => typeof path === "string" && path.length > 0);
}

async function scanUpload(details, paths) {
  const detections = [];
  const failures = [];
  for (const path of paths) {
    try {
      const result = await scanWithNativeHost(path, false);
      if (!result || result.success === false)
        throw new Error(result?.message || "ClamAV could not complete the upload scan");
      if (result.infected) detections.push({ path, result });
    } catch (error) {
      failures.push({ path, error: error.message });
    }
  }
  return { detections, failures };
}

if (browser.webRequest?.onBeforeRequest) {
  browser.webRequest.onBeforeRequest.addListener(async (details) => {
    await automaticScanningReady;
    if (!uploadScanning || !["POST", "PUT"].includes(details.method)) return {};

    const paths = uploadFilePaths(details);
    if (!paths.length) return {};
    const key = `${details.tabId}|${details.url}|${paths.join("|")}`;
    const override = uploadOverrides.get(key);
    if (override && override > Date.now()) {
      uploadOverrides.delete(key);
      return {};
    }
    uploadOverrides.delete(key);

    const scan = await scanUpload(details, paths);
    if (!scan.detections.length && !scan.failures.length) return {};

    const names = paths.map(path => path.split(/[\\/]/).pop()).join(", ");
    if (scan.detections.length) {
      uploadOverrides.set(key, Date.now() + UPLOAD_OVERRIDE_TTL_MS);
      const detected = scan.detections.map(item => item.path.split(/[\\/]/).pop()).join(", ");
      await browser.notifications.create(`clamav-upload-${details.requestId}`, {
        type: "basic",
        title: message("uploadThreatWarning"),
        message: message("uploadThreatMessage", [detected, new URL(details.url).hostname]),
        iconUrl: browser.runtime.getURL("logo.svg")
      });
      return { cancel: true };
    }

    await browser.notifications.create(`clamav-upload-scan-${details.requestId}`, {
      type: "basic",
      title: message("uploadScanIncomplete"),
      message: message("uploadScanIncompleteMessage", [names, scan.failures[0].error])
    });
    return {};
  }, { urls: ["<all_urls>"], types: ["xmlhttprequest", "main_frame", "sub_frame"] }, ["blocking", "requestBody"]);
}

function filename(download) {
  return download.filename ? download.filename.split(/[\\/]/).pop() : "download";
}

async function scanDownload(downloadId) {
  await automaticScanningReady;
  if (!automaticScanning) return;
  if (scannedDownloads.has(downloadId)) return;
  const items = await browser.downloads.search({ id: downloadId });
  const download = items[0];
  if (!download || download.state !== "complete" || !download.filename) return;
  scannedDownloads.add(downloadId);
  try {
    const result = await scanWithNativeHost(download.filename, true);
    if (!result || result.success === false) {
      throw new Error(result?.message || "ClamAV could not complete the scan");
    }
    const notification = {
      type: "basic",
      title: result.infected ? message("threatDetected") : message("downloadClean"),
      message: result.infected
        ? `${filename(download)}: ${result.message}`
        : message("downloadCleanMessage", filename(download))
    };
    let notificationId = `clamav-download-${downloadId}`;
    if (result.infected && result.quarantined) {
      notificationId = `clamav-quarantine-${downloadId}`;
      notification.message += message("openQuarantine");
    }
    await browser.notifications.create(notificationId, notification);
  } catch (error) {
    await browser.notifications.create(`clamav-download-error-${downloadId}`, {
      type: "basic",
      title: message("downloadScanFailed"),
      message: `${filename(download)}: ${error.message}`
    });
  }
}

browser.downloads.onCreated.addListener((download) => {
  if (download.state === "complete") {
    scanDownload(download.id).catch((error) => console.error("ClamAV download scan failed", error));
  }
});

browser.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === "complete") {
    scanDownload(delta.id).catch((error) => console.error("ClamAV download scan failed", error));
  }
});
