/* Attach the proof, then let Thunderbird send the message it composed. */

function addressOf(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(addressOf).filter(Boolean).join(", ");
  return value.email || value.id || "";
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

async function notice(message) {
  await browser.notifications.create({type: "basic", title: "GWyl Mail", message});
}

browser.compose.onBeforeSend.addListener(async (tab, details) => {
  const attachments = [];
  try {
    const listed = await browser.compose.listAttachments(tab.id);
    for (const item of listed) {
      if (item.name === "gwylproof.json") continue;
      const file = await browser.compose.getAttachmentFile(item.id);
      const bytes = new Uint8Array(await file.arrayBuffer());
      attachments.push({filename: item.name || file.name, content_b64: bytesToBase64(bytes)});
    }
  } catch (error) {
    await notice("Les pièces jointes n'ont pas pu être lues. L'envoi est annulé.");
    return {cancel: true};
  }
  let response;
  try {
    response = await fetch("http://127.0.0.1:8765/api/compose-proof", {
      method: "POST",
      headers: {"Content-Type": "application/json", "X-GWyl-Client": "1"},
      body: JSON.stringify({
        from: addressOf(details.from),
        to: addressOf(details.to),
        subject: details.subject || "",
        plain: details.plainTextBody || "",
        html: details.isPlainText ? "" : (details.body || ""),
        attachments
      }),
    });
  } catch (error) {
    await notice("L'application locale ne répond pas. L'envoi est annulé.");
    return {cancel: true};
  }
  if (!response.ok) {
    await notice("La preuve n'a pas pu être signée. L'envoi est annulé.");
    return {cancel: true};
  }
  const proof = await response.blob();
  const file = new File([proof], "gwylproof.json", {type: "application/json"});
  await browser.compose.addAttachment(tab.id, {file, name: "gwylproof.json"});
  return {cancel: false};
});
