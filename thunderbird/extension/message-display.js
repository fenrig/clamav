/* global messenger */

const BANNER_ID = "clamav-virus-warning";
let displayedMessageId = null;

function addActionButton(banner, id, text, command, confirmation, busyText) {
  let button = banner.querySelector(`#${id}`);
  if (button) return button;
  button = document.createElement("button");
  button.id = id;
  button.type = "button";
  button.textContent = text;
  button.addEventListener("click", async () => {
    try {
      if (!window.confirm(confirmation)) return;
      button.disabled = true;
      button.textContent = busyText;
      const response = await messenger.runtime.sendMessage({ command, messageId: displayedMessageId });
      if (response?.error) throw new Error(response.error);
      if (command === "deleteDisplayedMessage") banner.remove();
    } catch (error) {
      button.disabled = false;
      button.textContent = text;
      button.title = error.message || "ClamAV could not complete the action";
      console.error(`ClamAV: unable to ${command}`, error);
    }
  });
  return button;
}

function render(detections, messageId = displayedMessageId) {
  if (messageId !== null && messageId !== undefined) displayedMessageId = messageId;
  let banner = document.getElementById(BANNER_ID);
  if (!detections || !detections.length) {
    banner?.remove();
    return;
  }
  if (!banner) {
    banner = document.createElement("aside");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    document.body.prepend(banner);
  }
  banner.textContent = "";
  const hasPhishing = detections.some(detection => detection.kind === "phishing");
  const hasVirus = detections.some(detection => detection.kind === "virus");
  banner.classList.toggle("clamav-phishing-warning", hasPhishing);
  const heading = document.createElement("strong");
  heading.textContent = hasPhishing && hasVirus
    ? "⚠️ ClamAV detected a virus and a potentially malicious link"
    : hasPhishing
      ? "⚠️ ClamAV detected a potentially malicious link"
      : "🛑 ClamAV detected a virus in this message";
  banner.append(heading);
  if (hasPhishing) {
    const explanation = document.createElement("div");
    explanation.textContent = "This message may be a phishing attack. Do not click links or provide personal information.";
    banner.append(explanation);
  }
  for (const detection of detections) {
    const item = document.createElement("div");
    item.textContent = `${detection.attachmentName}: ${detection.message.split("\n", 1)[0]}`;
    banner.append(item);
  }
  let button = banner.querySelector("#clamav-rescan-attachments");
  if (!button) {
    button = document.createElement("button");
    button.id = "clamav-rescan-attachments";
    button.type = "button";
    button.textContent = "Rescan attachments and links";
    button.addEventListener("click", async () => {
      button.disabled = true;
      button.textContent = "Rescanning…";
      try {
        const response = await messenger.runtime.sendMessage({ command: "rescanDisplayedMessage" });
        if (response?.error) throw new Error(response.error);
      } catch (error) {
        button.disabled = false;
        button.textContent = "Rescan attachments and links";
        console.error("ClamAV: unable to rescan message attachments", error);
      }
    });
  }
  banner.append(button);

  const deleteButton = addActionButton(
    banner,
    "clamav-delete-message",
    "Delete this mail permanently",
    "deleteDisplayedMessage",
    "Permanently delete this mail? This cannot be undone and will bypass the Trash.",
    "Deleting…"
  );
  banner.append(deleteButton);
}

messenger.runtime.onMessage.addListener(request => {
  if (request?.command === "detection") render(request.detections);
});

messenger.runtime.sendMessage({ command: "getDetections" }).then(response => {
  render(response?.detections || [], response?.messageId ?? null);
}).catch(() => {});
