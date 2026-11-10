/* global messenger */

const BANNER_ID = "clamav-virus-warning";

function addActionButton(banner, id, text, command, confirmation, busyText) {
  let button = banner.querySelector(`#${id}`);
  if (button) return button;
  button = document.createElement("button");
  button.id = id;
  button.type = "button";
  button.textContent = text;
  button.addEventListener("click", async () => {
    if (!window.confirm(confirmation)) return;
    button.disabled = true;
    button.textContent = busyText;
    try {
      const response = await messenger.runtime.sendMessage({ command });
      if (response?.error) throw new Error(response.error);
      if (command === "deleteDisplayedMessage") banner.remove();
    } catch (error) {
      button.disabled = false;
      button.textContent = text;
      console.error(`ClamAV: unable to ${command}`, error);
    }
  });
  return button;
}

function render(detections) {
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

  const attachmentDetections = detections.filter(detection =>
    detection.partName && !detection.partName.startsWith("__clamav-")
  );
  if (attachmentDetections.length) {
    const attachmentButton = addActionButton(
      banner,
      "clamav-delete-attachments",
      attachmentDetections.length === 1 ? "Delete infected attachment" : "Delete infected attachments",
      "deleteDisplayedAttachments",
      attachmentDetections.length === 1
        ? "Permanently remove the infected attachment from this message?"
        : "Permanently remove the infected attachments from this message?",
      "Deleting…"
    );
    banner.append(attachmentButton);
  } else {
    banner.querySelector("#clamav-delete-attachments")?.remove();
  }

  const deleteButton = addActionButton(
    banner,
    "clamav-delete-message",
    "Delete this mail",
    "deleteDisplayedMessage",
    "Move this mail to the Trash?",
    "Deleting…"
  );
  banner.append(deleteButton);
}

messenger.runtime.onMessage.addListener(request => {
  if (request?.command === "detection") render(request.detections);
});

messenger.runtime.sendMessage({ command: "getDetections" }).then(response => {
  render(response?.detections || []);
}).catch(() => {});
