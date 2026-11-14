/* global browser */

const NATIVE_HOST = "org.clamav.thunderbird";
let nativePort = null;
let nativeCurrent = null;
const nativeQueue = [];
const scannedDownloads = new Set();

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
    nativePort.postMessage({ path: nativeCurrent.path, quarantine: nativeCurrent.quarantine });
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

function filename(download) {
  return download.filename ? download.filename.split(/[\\/]/).pop() : "download";
}

async function scanDownload(downloadId) {
  if (scannedDownloads.has(downloadId)) return;
  scannedDownloads.add(downloadId);
  const items = await browser.downloads.search({ id: downloadId });
  const download = items[0];
  if (!download || download.state !== "complete" || !download.exists) return;
  try {
    const result = await scanWithNativeHost(download.filename, true);
    if (!result || result.success === false) {
      throw new Error(result?.message || "ClamAV could not complete the scan");
    }
    await browser.notifications.create(`clamav-download-${downloadId}`, {
      type: "basic",
      title: result.infected ? "ClamAV: threat detected" : "ClamAV: download clean",
      message: result.infected
        ? `${filename(download)}: ${result.message}`
        : `${filename(download)} was scanned and no viruses were found.`
    });
  } catch (error) {
    await browser.notifications.create(`clamav-download-error-${downloadId}`, {
      type: "basic",
      title: "ClamAV download scan failed",
      message: `${filename(download)}: ${error.message}`
    });
  }
}

browser.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === "complete") {
    scanDownload(delta.id).catch((error) => console.error("ClamAV download scan failed", error));
  }
});
