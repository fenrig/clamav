/* global messenger */

const NATIVE_HOST = "org.clamav.thunderbird";
const MENU_ID = "clamav-scan-attachment";
const FORCE_MENU_ID = "clamav-force-scan-attachment";
const MESSAGE_MENU_ID = "clamav-scan-message-attachments";
const MESSAGE_FORCE_MENU_ID = "clamav-force-scan-message-attachments";
const EMAIL_MENU_ID = "clamav-scan-email";
const EMAIL_FORCE_MENU_ID = "clamav-force-scan-email";
const LIBRARY_MENU_ID = "clamav-scan-library";
const LIBRARY_CANCEL_MENU_ID = "clamav-cancel-library-scan";
const MESSAGE_LINKS_PART = "__clamav-message-links";
const VIRUS_TAG_KEY = "clamav-virus";
const PHISHING_TAG_KEY = "clamav-phishing";
const DEFAULT_ACCOUNT = { autoScan: true };
const DEFAULT_CACHE = { maxEntries: 1000, maxAgeDays: 180 };
const detections = new Map();
let libraryScan = null;
let diagnosticLogging = false;

async function loadDiagnosticLogging() {
  try {
    const stored = await messenger.storage.local.get("diagnosticLogging");
    diagnosticLogging = stored.diagnosticLogging === true;
  } catch (_) {
    diagnosticLogging = false;
  }
}

loadDiagnosticLogging();
messenger.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && changes.diagnosticLogging) {
    diagnosticLogging = changes.diagnosticLogging.newValue === true;
  }
});

async function registerMessageDisplayScripts() {
  if (!messenger.messageDisplayScripts) return;
  try {
    await messenger.messageDisplayScripts.register({
      js: [{ file: "message-display.js" }],
      css: [{ file: "message-display.css" }],
      runAt: "document_end"
    });
    const tabs = await messenger.tabs.query({});
    for (const tab of tabs) {
      if (!["mail", "messageDisplay"].includes(tab.type)) continue;
      try {
        await messenger.tabs.executeScript(tab.id, { file: "message-display.js" });
        await messenger.tabs.insertCSS(tab.id, { file: "message-display.css" });
      } catch (_) {
        // The tab may have closed or may not contain a displayable message.
      }
    }
  } catch (error) {
    console.error("ClamAV: unable to register message display warning", error);
  }
}

registerMessageDisplayScripts();

messenger.menus.create({ id: EMAIL_MENU_ID, title: "Scan email for viruses and phishing", contexts: ["message_list"] });
messenger.menus.create({ id: EMAIL_FORCE_MENU_ID, title: "Force rescan email for viruses and phishing", contexts: ["message_list"] });
messenger.menus.create({ id: LIBRARY_MENU_ID, title: "Scan full mail library for viruses and phishing", contexts: ["tools_menu"] });
messenger.menus.create({ id: LIBRARY_CANCEL_MENU_ID, title: "Cancel full mail library scan", contexts: ["tools_menu"], visible: false });
messenger.menus.create({ id: MESSAGE_MENU_ID, title: "Scan message attachments for viruses", contexts: ["message_list"] });
messenger.menus.create({ id: MESSAGE_FORCE_MENU_ID, title: "Force rescan all message attachments for viruses", contexts: ["message_list"] });
messenger.menus.create({ id: MENU_ID, title: "Scan attachment for viruses", contexts: ["message_attachments"] });
messenger.menus.create({ id: FORCE_MENU_ID, title: "Force rescan attachment for viruses", contexts: ["message_attachments"] });

function safeFilename(name) {
  return (name || "attachment").replace(/[^a-zA-Z0-9._-]/g, "_");
}

function logScan(message, details = {}) {
  if (!diagnosticLogging) return;
  console.info(`ClamAV: ${message}`, details);
}

async function setLibraryCancelMenuVisible(visible) {
  await messenger.menus.update(LIBRARY_CANCEL_MENU_ID, { visible }).catch(() => {});
}

async function cleanupTemporaryDownloads() {
  try {
    const downloads = await messenger.downloads.search({ query: ["clamav-scan"] });
    for (const download of downloads) {
      if (!download.filename || !(/[\\/]clamav-scan[\\/]/.test(download.filename))) continue;
      await messenger.downloads.removeFile(download.id).catch(() => {});
    }
  } catch (error) {
    console.error("ClamAV: unable to clean temporary scan files", error);
  }
}

cleanupTemporaryDownloads();

async function settings() {
  const stored = await messenger.storage.local.get(["accounts", "cache"]);
  return { accounts: stored.accounts || {}, cache: { ...DEFAULT_CACHE, ...(stored.cache || {}) } };
}

async function accountSettings(accountId) {
  const stored = await settings();
  return { ...DEFAULT_ACCOUNT, ...(stored.accounts[accountId] || {}) };
}

async function sha256(file) {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function cachedResult(hash) {
  const stored = await settings();
  const entries = stored.cache.entries || {};
  const entry = entries[hash];
  if (!entry) return null;
  if (Date.now() - entry.timestamp > stored.cache.maxAgeDays * 86400000) {
    delete entries[hash];
    await messenger.storage.local.set({ cache: { ...stored.cache, entries } });
    return null;
  }
  // Treat a successful lookup as a cache hit: refresh its age so frequently
  // used detections stay near the front of the recency-ordered cache.
  entry.timestamp = Date.now();
  const orderedEntries = Object.fromEntries(
    Object.entries(entries).sort(([, left], [, right]) => right.timestamp - left.timestamp)
  );
  await messenger.storage.local.set({ cache: { ...stored.cache, entries: orderedEntries } });
  return orderedEntries[hash].result;
}

async function saveResult(hash, result) {
  // Never cache clean or incomplete scans. A new signature database can turn
  // a previously clean file into a detection, while a cached detection can be
  // bypassed explicitly with the force-rescan action.
  if (!result.infected) return;
  const stored = await settings();
  const entries = stored.cache.entries || {};
  entries[hash] = { timestamp: Date.now(), result };
  const cutoff = Date.now() - stored.cache.maxAgeDays * 86400000;
  for (const [key, value] of Object.entries(entries)) {
    if (value.timestamp < cutoff) delete entries[key];
  }
  const keys = Object.keys(entries).sort((a, b) => entries[b].timestamp - entries[a].timestamp);
  for (const key of keys.slice(stored.cache.maxEntries)) delete entries[key];
  await messenger.storage.local.set({ cache: { ...stored.cache, entries } });
}

async function waitForDownload(downloadId) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => messenger.downloads.onChanged.removeListener(listener);
    const fail = error => {
      if (settled) return;
      cleanup();
      settled = true;
      reject(error);
    };
    const finish = () => messenger.downloads.search({ id: downloadId }).then(([download]) => {
      if (!download) throw new Error("Thunderbird could not find the downloaded attachment");
      if (settled) return;
      cleanup();
      settled = true;
      resolve(download);
    }).catch(fail);
    const listener = delta => {
      if (delta.id !== downloadId || !delta.state) return;
      if (delta.state.current === "complete") {
        finish();
      } else if (delta.state.current === "interrupted") {
        const reason = delta.error?.current;
        fail(new Error(reason
          ? `Thunderbird could not save the attachment: ${reason}`
          : "Thunderbird could not save the attachment"));
      }
    };
    messenger.downloads.onChanged.addListener(listener);

    messenger.downloads.search({ id: downloadId }).then(([download]) => {
      if (settled || !download) return;
      if (download.state === "complete") {
        cleanup();
        settled = true;
        resolve(download);
      } else if (download.state === "interrupted") {
        const reason = download.error;
        fail(new Error(reason
          ? `Thunderbird could not save the attachment: ${reason}`
          : "Thunderbird could not save the attachment"));
      }
    }).catch(fail);
  });
}

async function showResult(result, automatic, attachmentName, quiet = false) {
  if ((automatic || quiet) && !result.infected) return;
  const name = (attachmentName || "attachment").split(/[\\/]/).pop();
  const phishing = isPhishingResult(result);
  const notificationId = await messenger.notifications.create({
    type: "basic",
    title: result.infected
      ? `${phishing ? "⚠️ Possible phishing link" : "🛑 Virus detected"}: ${name}`
      : `✅ ClamAV scan complete: ${name}`,
    message: result.infected
      ? `${phishing ? "This message may be a phishing attack. Do not click its links." : "This attachment was identified as dangerous."}\n\nAttachment: ${name}\n\n${result.message}`
      : `Attachment: ${name}\n\n${result.message}`,
    iconUrl: messenger.runtime.getURL("logo.svg")
  });
}

function isPhishingResult(result) {
  return /phishing|spoofeddomain/i.test(result?.message || "");
}

async function setMessageSecurityTags(messageId, current) {
  try {
    const tags = await messenger.messages.tags.list();
    const definitions = [
      [VIRUS_TAG_KEY, "ClamAV: Virus", "#c00000"],
      [PHISHING_TAG_KEY, "ClamAV: Phishing", "#c2410c"]
    ];
    for (const [key, name, color] of definitions) {
      if (current.some(detection => detection.kind === key.replace("clamav-", "")) && !tags.some(tag => tag.key === key)) {
        try {
          await messenger.messages.tags.create(key, name, color);
        } catch (_) {
          // Another scan may have created the shared tag concurrently.
        }
      }
    }
    const message = await messenger.messages.get(messageId);
    const messageTags = Array.isArray(message.tags) ? message.tags : [];
    const nextTags = messageTags.filter(tag => tag !== VIRUS_TAG_KEY && tag !== PHISHING_TAG_KEY);
    if (current.some(detection => detection.kind === "virus")) nextTags.push(VIRUS_TAG_KEY);
    if (current.some(detection => detection.kind === "phishing")) nextTags.push(PHISHING_TAG_KEY);
    const uniqueTags = [...new Set(nextTags)];
    if (uniqueTags.length !== messageTags.length || uniqueTags.some((tag, index) => tag !== messageTags[index])) {
      await messenger.messages.update(messageId, { tags: uniqueTags });
    }
  } catch (error) {
    console.error("ClamAV: unable to update message security tags", error);
  }
}

function attachmentKey(attachment) {
  return attachment.partName || attachment.name || "attachment";
}

function detectionsFromTags(message) {
  const tags = Array.isArray(message?.tags) ? message.tags : [];
  const detections = [];
  if (tags.includes(VIRUS_TAG_KEY)) {
    detections.push({
      partName: "__clamav-virus-tag",
      attachmentName: "Attachment",
      kind: "virus",
      message: "ClamAV previously detected a virus in this message. Rescan to confirm the current result."
    });
  }
  if (tags.includes(PHISHING_TAG_KEY)) {
    detections.push({
      partName: "__clamav-phishing-tag",
      attachmentName: "Message links",
      kind: "phishing",
      message: "ClamAV previously detected a potentially malicious link in this message."
    });
  }
  return detections;
}

async function cachedDetectionsForMessage(message) {
  const detections = [];
  try {
    const attachments = await messenger.messages.listAttachments(message.id);
    for (const attachment of attachments) {
      const file = await messenger.messages.getAttachmentFile(message.id, attachment.partName);
      const result = await cachedResult(await sha256(file));
      if (result?.infected) {
        detections.push({
          partName: attachment.partName,
          attachmentName: attachment.name || "attachment",
          kind: isPhishingResult(result) ? "phishing" : "virus",
          message: result.message
        });
      }
    }
    const full = await messenger.messages.getFull(message.id, { decodeContent: true });
    for (const [index, part] of messageTextParts(full).entries()) {
      const contentType = part.contentType.toLowerCase().split(";", 1)[0];
      const result = await cachedResult(await sha256(new Blob([part.body], { type: contentType })));
      if (result?.infected) {
        detections.push({
          partName: part.partName || `${MESSAGE_LINKS_PART}-${index}`,
          attachmentName: "Message links",
          kind: isPhishingResult(result) ? "phishing" : "virus",
          message: result.message
        });
      }
    }
  } catch (error) {
    console.error("ClamAV: unable to restore cached detections", error);
  }
  return detections;
}

async function clearMessageInfected(messageId, attachment) {
  const current = detections.get(messageId) || [];
  const remaining = current.filter(detection => detection.partName !== attachmentKey(attachment));
  if (remaining.length) {
    detections.set(messageId, remaining);
  } else {
    detections.delete(messageId);
  }
  await setMessageSecurityTags(messageId, remaining);
  await updateDisplayedMessage(messageId, remaining);
}

async function updateDisplayedMessage(messageId, current) {
  const tabs = await messenger.tabs.query({});
  for (const tab of tabs) {
    try {
      const displayed = await messenger.messageDisplay.getDisplayedMessage(tab.id);
      if (displayed && displayed.id === messageId) {
        await messenger.tabs.sendMessage(tab.id, { command: "detection", detections: current });
      }
    } catch (_) {
      // The tab may not be a message display tab or may have closed.
    }
  }
}

async function displayedMessageId(sender) {
  const message = sender.tab
    ? await messenger.messageDisplay.getDisplayedMessage(sender.tab.id)
    : await messenger.messageDisplay.getDisplayedMessage();
  const messageId = Number(message?.id);
  if (!Number.isInteger(messageId)) throw new Error("Thunderbird did not provide a valid message ID");
  return messageId;
}

async function deleteDisplayedAttachments(messageId) {
  const current = detections.get(messageId) || [];
  const attachments = await messenger.messages.listAttachments(messageId);
  const attachmentParts = new Set(attachments.map(attachment => attachment.partName));
  const partNames = current
    .map(detection => detection.partName)
    .filter(partName => attachmentParts.has(partName));
  if (!partNames.length) throw new Error("No infected attachments were found in this message");
  await messenger.messages.deleteAttachments(messageId, [...new Set(partNames)]);
  const remaining = current.filter(detection => !partNames.includes(detection.partName));
  if (remaining.length) detections.set(messageId, remaining);
  else detections.delete(messageId);
  await setMessageSecurityTags(messageId, remaining);
  await updateDisplayedMessage(messageId, remaining);
}

async function rescanMessageAttachments(messageId, force = true, quiet = true) {
  const message = await messenger.messages.get(messageId);
  if (!message?.folder?.accountId) throw new Error("Thunderbird did not provide the message account");
  logScan("scanning message", {
    messageId: message.id,
    subject: message.subject || "(no subject)",
    automatic: false,
    force
  });
  let linksScanned = 0;
  try {
    linksScanned = await scanMessageLinks(message.id, message.folder.accountId, false, force, quiet);
  } catch (error) {
    await messenger.notifications.create({ type: "basic", title: "ClamAV link scan failed", message: error.message });
  }
  const attachments = await messenger.messages.listAttachments(message.id);
  for (const attachment of attachments) {
    await scanAttachment({ ...attachment, messageId: message.id }, message.folder.accountId, false, force, quiet);
  }
  return linksScanned + attachments.length;
}

function messageTextParts(part, result = []) {
  if (!part) return result;
  const contentType = part.contentType?.toLowerCase().split(";", 1)[0];
  if (["text/html", "text/plain"].includes(contentType) &&
      part.disposition !== "attachment" && typeof part.body === "string") {
    result.push(part);
  }
  for (const child of part.parts || []) messageTextParts(child, result);
  return result;
}

async function scanMessageLinks(messageId, accountId, automatic = false, force = false, quiet = false) {
  const account = await accountSettings(accountId);
  if (automatic && !account.autoScan) return 0;
  const full = await messenger.messages.getFull(messageId, { decodeContent: true });
  const parts = messageTextParts(full);
  let scanned = 0;
  for (const [index, part] of parts.entries()) {
    const key = part.partName || `${MESSAGE_LINKS_PART}-${index}`;
    logScan("scanning message text", { messageId, part: key, contentType: part.contentType, automatic, force });
    const contentType = part.contentType.toLowerCase().split(";", 1)[0];
    const file = new Blob([part.body], { type: contentType });
    const hash = await sha256(file);
    const cached = force ? null : await cachedResult(hash);
    const detection = { partName: key, name: "Message links", attachmentName: "Message links" };
    if (cached) {
      logScan("message text result from cache", { messageId, part: key, infected: cached.infected });
      await publishDetection(messageId, cached, detection);
      await showResult(cached, automatic, detection.name, quiet);
      scanned++;
      continue;
    }

    let downloadId;
    let objectUrl;
    try {
      objectUrl = URL.createObjectURL(file);
      downloadId = await messenger.downloads.download({
        url: objectUrl,
        filename: `clamav-scan/message-${messageId}-${index}.${contentType === "text/plain" ? "txt" : "html"}`,
        saveAs: false,
        conflictAction: "uniquify"
      });
      const download = await waitForDownload(downloadId);
      const scan = await messenger.runtime.sendNativeMessage(NATIVE_HOST, { path: download.filename });
      if (!scan || scan.success === false) throw new Error(scan?.message || "ClamAV could not complete the scan");
      await saveResult(hash, scan);
      if (scan.infected) {
        await publishDetection(messageId, scan, detection);
      } else {
        await clearMessageInfected(messageId, detection);
      }
      await showResult(scan, automatic, detection.name, quiet);
      logScan("message text scan complete", { messageId, part: key, infected: scan.infected, sha256: scan.sha256 });
      scanned++;
    } catch (error) {
      await messenger.notifications.create({ type: "basic", title: "ClamAV link scan failed", message: error.message });
    } finally {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      if (downloadId !== undefined) await messenger.downloads.removeFile(downloadId).catch(() => {});
    }
  }
  return scanned;
}

async function publishDetection(messageId, result, attachment) {
  if (!result.infected) return;
  const current = detections.get(messageId) || [];
  const key = attachmentKey(attachment);
  const remaining = current.filter(detection => detection.partName !== key);
  remaining.push({
    partName: key,
    attachmentName: attachment.name || "attachment",
    kind: isPhishingResult(result) ? "phishing" : "virus",
    message: result.message
  });
  detections.set(messageId, remaining);
  await setMessageSecurityTags(messageId, remaining);
  await updateDisplayedMessage(messageId, remaining);
}

messenger.runtime.onMessage.addListener(async (request, sender) => {
  if (request?.command === "deleteDisplayedMessage") {
    try {
      const messageId = await displayedMessageId(sender);
      // Use the account's normal deletion behavior (normally move to Trash).
      await messenger.messages.delete([messageId], false);
      detections.delete(messageId);
      if (sender.tab) {
        await messenger.tabs.sendMessage(sender.tab.id, {
          command: "detection",
          detections: []
        }).catch(() => {});
      }
      return { ok: true };
    } catch (error) {
      await messenger.notifications.create({
        type: "basic",
        title: "ClamAV could not delete the message",
        message: error.message
      });
      return { error: error.message };
    }
  }
  if (request?.command === "deleteDisplayedAttachments") {
    try {
      await deleteDisplayedAttachments(await displayedMessageId(sender));
      return { ok: true };
    } catch (error) {
      await messenger.notifications.create({
        type: "basic",
        title: "ClamAV could not delete the attachments",
        message: error.message
      });
      return { error: error.message };
    }
  }
  if (request?.command === "rescanDisplayedMessage") {
    try {
      const messageId = await displayedMessageId(sender);
      const scanned = await rescanMessageAttachments(messageId, true);
      if (!scanned) {
        await messenger.notifications.create({
          type: "basic",
          title: "ClamAV scan complete",
          message: "This message has no attachments to scan."
        });
      } else if (!(detections.get(messageId) || []).length) {
        await messenger.notifications.create({
          type: "basic",
          title: "ClamAV scan complete",
          message: "No viruses or malicious links were found."
        });
      }
      return { ok: true };
    } catch (error) {
      await messenger.notifications.create({
        type: "basic",
        title: "ClamAV scan failed",
        message: error.message
      });
      return { error: error.message };
    }
  }
  if (!request || request.command !== "getDetections" || !sender.tab) return undefined;
  try {
    const message = await messenger.messageDisplay.getDisplayedMessage(sender.tab.id);
    if (!message) return { detections: [] };
    let current = detections.get(message.id);
    if (!current) {
      current = await cachedDetectionsForMessage(message);
      if (current.length) detections.set(message.id, current);
    }
    return { detections: current.length ? current : detectionsFromTags(message) };
  } catch (_) {
    return { detections: [] };
  }
});

async function scanAttachment(attachment, accountId, automatic = false, force = false, quiet = false) {
  const account = await accountSettings(accountId);
  if (automatic && !account.autoScan) return;
  let downloadId;
  let objectUrl;
  try {
    logScan("scanning attachment", {
      messageId: attachment.messageId,
      attachment: attachment.name || attachment.partName,
      automatic,
      force
    });
    const file = await messenger.messages.getAttachmentFile(attachment.messageId, attachment.partName);
    const hash = await sha256(file);
    const cached = force ? null : await cachedResult(hash);
    if (cached) {
      logScan("attachment result from cache", { messageId: attachment.messageId, attachment: attachment.name, infected: cached.infected });
      await publishDetection(attachment.messageId, cached, attachment);
      await showResult(cached, automatic, attachment.name, quiet);
      return;
    }
    objectUrl = URL.createObjectURL(file);
    downloadId = await messenger.downloads.download({ url: objectUrl, filename: `clamav-scan/${safeFilename(attachment.name)}`, saveAs: false, conflictAction: "uniquify" });
    const download = await waitForDownload(downloadId);
    const result = await messenger.runtime.sendNativeMessage(NATIVE_HOST, { path: download.filename });
    if (!result || result.success === false) {
      throw new Error(result?.message || "ClamAV could not complete the scan");
    }
    await saveResult(hash, result);
    if (result.infected) {
      await publishDetection(attachment.messageId, result, attachment);
    } else {
      await clearMessageInfected(attachment.messageId, attachment);
    }
    await showResult(result, automatic, attachment.name, quiet);
    logScan("attachment scan complete", {
      messageId: attachment.messageId,
      attachment: attachment.name,
      infected: result.infected,
      sha256: result.sha256
    });
  } catch (error) {
    await messenger.notifications.create({ type: "basic", title: "ClamAV scan failed", message: error.message });
  } finally {
    if (objectUrl) URL.revokeObjectURL(objectUrl);
    if (downloadId !== undefined) await messenger.downloads.removeFile(downloadId).catch(() => {});
  }
}

function collectRealFolders(folder, result = []) {
  if (!folder || folder.isVirtual || folder.isUnified || folder.isTag) return result;
  if (!folder.isRoot) result.push(folder);
  for (const child of folder.subFolders || []) collectRealFolders(child, result);
  return result;
}

async function scanFullLibrary() {
  if (libraryScan) {
    await messenger.notifications.create({
      type: "basic",
      title: "ClamAV library scan already running",
      message: "Use the cancel action in the Tools menu to stop it."
    });
    return;
  }
  const scanState = { cancelled: false };
  libraryScan = scanState;
  await setLibraryCancelMenuVisible(true);
  let foldersScanned = 0;
  let messagesScanned = 0;
  let partsScanned = 0;
  let detectionsFound = 0;
  try {
    const accounts = await messenger.accounts.list(true);
    for (const account of accounts) {
      for (const folder of collectRealFolders(account.rootFolder)) {
        if (scanState.cancelled) throw new Error("Library scan cancelled");
        foldersScanned++;
        try {
          let page = await messenger.messages.list(folder);
          while (page) {
            for (const message of page.messages || []) {
              if (scanState.cancelled) throw new Error("Library scan cancelled");
              messagesScanned++;
              partsScanned += await rescanMessageAttachments(message.id, true, true);
              if ((detections.get(message.id) || []).length) detectionsFound++;
              logScan("library message scan complete", {
                account: account.id,
                folder: folder.path,
                messageId: message.id,
                subject: message.subject || "(no subject)",
                messagesScanned,
                partsScanned
              });
            }
            if (!page.id) break;
            page = await messenger.messages.continueList(page.id);
          }
        } catch (error) {
          if (scanState.cancelled) throw error;
          console.error("ClamAV: unable to scan folder", folder.path, error);
        }
      }
    }
    if (scanState.cancelled) throw new Error("Library scan cancelled");
    await messenger.notifications.create({
      type: "basic",
      title: "ClamAV library scan complete",
      message: detectionsFound
        ? `Scanned ${messagesScanned} messages and ${partsScanned} attachments or message text parts. Detections found in ${detectionsFound} messages.`
        : `Scanned ${messagesScanned} messages and ${partsScanned} attachments or message text parts. No viruses or malicious links were found.`
    });
  } catch (error) {
    await messenger.notifications.create({
      type: "basic",
      title: scanState.cancelled ? "ClamAV library scan cancelled" : "ClamAV library scan failed",
      message: scanState.cancelled
        ? `Scanned ${messagesScanned} messages before cancellation.`
        : error.message
    });
  } finally {
    if (libraryScan === scanState) libraryScan = null;
    await setLibraryCancelMenuVisible(false);
  }
}

messenger.menus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === LIBRARY_CANCEL_MENU_ID) {
    if (libraryScan) {
      libraryScan.cancelled = true;
      logScan("library scan cancellation requested");
    }
    return;
  }

  if (info.menuItemId === LIBRARY_MENU_ID) {
    await scanFullLibrary();
    return;
  }

  if ([EMAIL_MENU_ID, EMAIL_FORCE_MENU_ID].includes(info.menuItemId)) {
    try {
      let page = info.selectedMessages;
      let scanned = 0;
      let messagesScanned = 0;
      let detectionsFound = 0;
      while (page) {
        for (const message of page.messages || []) {
          messagesScanned++;
          scanned += await rescanMessageAttachments(
            message.id,
            info.menuItemId === EMAIL_FORCE_MENU_ID
          );
          if ((detections.get(message.id) || []).length) detectionsFound++;
        }
        if (!page.id) break;
        page = await messenger.messages.continueList(page.id);
      }
      if (!scanned) {
        await messenger.notifications.create({
          type: "basic",
          title: "ClamAV scan complete",
          message: "The selected email has no attachments or message text parts to scan."
        });
      } else {
        await messenger.notifications.create({
          type: "basic",
          title: "ClamAV scan complete",
          message: detectionsFound
            ? `Scanned ${messagesScanned} messages. Detections found in ${detectionsFound} messages.`
            : `Scanned ${messagesScanned} messages. No viruses or malicious links were found.`
        });
      }
    } catch (error) {
      await messenger.notifications.create({
        type: "basic",
        title: "ClamAV scan failed",
        message: error.message
      });
    }
    return;
  }

  if ([MESSAGE_MENU_ID, MESSAGE_FORCE_MENU_ID].includes(info.menuItemId)) {
    try {
      let page = info.selectedMessages;
      let scanned = 0;
      while (page) {
        for (const message of page.messages || []) {
          const accountId = message.folder?.accountId || info.displayedFolder?.accountId;
          if (!accountId) throw new Error("Thunderbird did not provide the message account");
          const attachments = await messenger.messages.listAttachments(message.id);
          logScan("scanning message attachments", {
            messageId: message.id,
            subject: message.subject || "(no subject)",
            attachments: attachments.length,
            automatic: false,
            force: info.menuItemId === MESSAGE_FORCE_MENU_ID
          });
          for (const attachment of attachments) {
            scanned++;
            await scanAttachment({ ...attachment, messageId: message.id }, accountId,
              false, info.menuItemId === MESSAGE_FORCE_MENU_ID);
          }
        }
        if (!page.id) break;
        page = await messenger.messages.continueList(page.id);
      }
      if (!scanned) {
        await messenger.notifications.create({
          type: "basic",
          title: "ClamAV scan complete",
          message: "The selected message has no attachments to scan."
        });
      }
    } catch (error) {
      await messenger.notifications.create({
        type: "basic",
        title: "ClamAV scan failed",
        message: error.message
      });
    }
    return;
  }

  if (![MENU_ID, FORCE_MENU_ID].includes(info.menuItemId) || !info.attachments || !info.attachments.length) return;
  try {
    const attachment = info.attachments[0];
    let message = tab?.id === undefined
      ? null
      : await messenger.messageDisplay.getDisplayedMessage(tab.id);
    message ||= await messenger.messageDisplay.getDisplayedMessage();
    const messageId = Number(message?.id ?? attachment.messageId);
    if (!Number.isInteger(messageId)) throw new Error("Thunderbird did not provide a valid message ID");
    message ||= await messenger.messages.get(messageId);
    await scanAttachment({ ...attachment, messageId }, message.folder.accountId,
      false, info.menuItemId === FORCE_MENU_ID);
  } catch (error) {
    await messenger.notifications.create({
      type: "basic",
      title: "ClamAV scan failed",
      message: error.message
    });
  }
});

messenger.messages.onNewMailReceived.addListener(async (folder, messages) => {
  const account = await accountSettings(folder.accountId);
  if (!account.autoScan) return;
  let page = Array.isArray(messages) ? { messages, id: null } : messages;
  while (page) {
    for (const message of page.messages || []) {
      const attachments = await messenger.messages.listAttachments(message.id);
      logScan("automatic message scan", {
        messageId: message.id,
        subject: message.subject || "(no subject)",
        attachments: attachments.length,
        automatic: true,
        force: false
      });
      try {
        await scanMessageLinks(message.id, folder.accountId, true);
      } catch (error) {
        console.error("ClamAV: unable to scan message links", error);
      }
      for (const attachment of attachments) {
        await scanAttachment({ ...attachment, messageId: message.id }, folder.accountId, true);
      }
    }
    if (!page.id) break;
    page = await messenger.messages.continueList(page.id);
  }
}, true);
