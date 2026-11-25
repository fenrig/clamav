/* global browser */

const NATIVE_HOST = "org.clamav.thunderbird";
const message = (key, substitutions) => browser.i18n.getMessage(key, substitutions) || key;
let nativePort = null;
const nativeQueue = [];
const nativeRequests = new Map();
let nativeRequestSequence = 0;
let nativeWorkers = 2;

function maximumNativeWorkers() {
  const processors = Math.max(1, Number(navigator.hardwareConcurrency) || 1);
  return Math.max(1, Math.floor(processors / 2));
}

function normalizeNativeWorkers(value) {
  return Math.max(1, Math.min(maximumNativeWorkers(), Number(value) || 2));
}

browser.storage.local.get({ nativeWorkers: 2 }).then((settings) => {
  nativeWorkers = normalizeNativeWorkers(settings.nativeWorkers);
}).catch(() => {});
const scannedDownloads = new Set();
const uploadOverrides = new Map();
const UPLOAD_OVERRIDE_TTL_MS = 15 * 60 * 1000;
let automaticScanning = true;
let uploadScanning = true;
let cleanNotifications = false;

const automaticScanningReady = browser.storage.local.get({ automaticScanning: true, uploadScanning: true, cleanNotifications: false }).then((settings) => {
  automaticScanning = settings.automaticScanning !== false;
  uploadScanning = settings.uploadScanning !== false;
  cleanNotifications = settings.cleanNotifications === true;
}).catch(() => {
  automaticScanning = true;
  uploadScanning = true;
  cleanNotifications = false;
});

browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.automaticScanning)
    automaticScanning = changes.automaticScanning.newValue !== false;
  if (areaName === "local" && changes.uploadScanning)
    uploadScanning = changes.uploadScanning.newValue !== false;
  if (areaName === "local" && changes.cleanNotifications)
    cleanNotifications = changes.cleanNotifications.newValue === true;
  if (areaName === "local" && changes.nativeWorkers) {
    nativeWorkers = normalizeNativeWorkers(changes.nativeWorkers.newValue);
    pumpNativeQueue();
  }
});

function notificationIcon(kind = "default") {
  const filename = kind === "success"
    ? "notification-success.svg"
    : (kind === "threat" ? "notification-threat.svg" : "notification-logo.svg");
  return browser.runtime.getURL(filename);
}

function pumpNativeQueue() {
  if (nativeQueue.length === 0 && nativeRequests.size === 0) return;
  if (!nativePort) {
    try {
      nativePort = browser.runtime.connectNative(NATIVE_HOST);
    } catch (error) {
      nativeQueue.shift().reject(error);
      pumpNativeQueue();
      return;
    }
    nativePort.onMessage.addListener((message) => {
      const request = nativeRequests.get(message?.request_id);
      if (!request) return;
      nativeRequests.delete(message.request_id);
      request.resolve(message);
      pumpNativeQueue();
    });
    nativePort.onDisconnect.addListener(() => {
      const error = browser.runtime.lastError?.message || "ClamAV native host disconnected";
      const requests = Array.from(nativeRequests.values());
      nativeRequests.clear();
      nativePort = null;
      for (const request of requests) request.reject(new Error(error));
      pumpNativeQueue();
    });
  }
  while (nativeRequests.size < nativeWorkers && nativeQueue.length > 0) {
    const request = nativeQueue.shift();
    request.requestId = `scan-${++nativeRequestSequence}`;
    nativeRequests.set(request.requestId, request);
    try {
      nativePort.postMessage({ request_id: request.requestId, path: request.path,
        quarantine: request.quarantine, component: "firefox", origin: request.origin,
        metadata: request.metadata, workers: nativeWorkers });
    } catch (error) {
      nativeRequests.delete(request.requestId);
      nativePort = null;
      request.reject(error);
      pumpNativeQueue();
      break;
    }
  }
}

function scanWithNativeHost(path, quarantine = false, origin = "", metadata = {}) {
  return new Promise((resolve, reject) => {
    nativeQueue.push({ path, quarantine, origin, metadata, resolve, reject });
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
        message: message("uploadThreatMessage", [detected]),
        iconUrl: notificationIcon("threat")
      });
      return { cancel: true };
    }

    await browser.notifications.create(`clamav-upload-scan-${details.requestId}`, {
      type: "basic",
      title: message("uploadScanIncomplete"),
      message: message("uploadScanIncompleteMessage", [names]),
      iconUrl: notificationIcon("default")
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
    const sourceUrl = download.url || download.referrer || "";
    const result = await scanWithNativeHost(download.filename, true, sourceUrl,
      { source_url: sourceUrl });
    if (!result || result.success === false) {
      throw new Error(result?.message || "ClamAV could not complete the scan");
    }
    if (!result.infected && !cleanNotifications) return;
    const quarantineFailure = result.infected && !result.quarantined && result.quarantine_reason
      ? `\n\n${message("quarantineFailureReason", result.quarantine_reason)}` : "";
    const notification = {
      type: "basic",
      title: result.infected
        ? (result.quarantined ? message("downloadQuarantined") : message("threatDetected"))
        : message("downloadClean"),
      message: result.infected
        ? (result.quarantined
          ? message("downloadQuarantinedMessage", filename(download))
          : message("downloadThreatMessage", filename(download))) + quarantineFailure
        : message("downloadCleanMessage", filename(download)),
      iconUrl: notificationIcon(result.infected ? "threat" : "success")
    };
    let notificationId = `clamav-download-${downloadId}`;
    if (result.infected && result.quarantined) {
      notificationId = `clamav-quarantine-${downloadId}`;
    }
    await browser.notifications.create(notificationId, notification);
  } catch (error) {
    await browser.notifications.create(`clamav-download-error-${downloadId}`, {
      type: "basic",
      title: message("downloadScanFailed"),
      message: message("downloadScanFailedMessage", filename(download)),
      iconUrl: notificationIcon("default")
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
