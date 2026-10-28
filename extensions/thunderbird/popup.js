document.getElementById("go").onclick = async () => {
  const out = document.getElementById("out");
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    const message = await browser.messageDisplay.getDisplayedMessage(tabs[0].id);
    if (!message) {
      out.textContent = "Aucun message affiché.";
      return;
    }
    const raw = await browser.messages.getRaw(message.id);
    const file = new File([raw], "message.eml", { type: "message/rfc822" });
    const body = new FormData();
    body.append("eml", file, "message.eml");
    if (document.getElementById("deg").checked) body.append("allow_degraded", "1");
    const res = await fetch("http://127.0.0.1:8765/api/check", {
      method: "POST",
      headers: { "X-GWyl-Client": "1" },
      body,
    });
    const data = await res.json();
    out.textContent = (res.ok ? "Accepté\n" : "Refusé\n") + JSON.stringify(data, null, 2);
  } catch (err) {
    out.textContent = "Vérification impossible. Lancez : gwyl-mail ui\n" + err;
  }
};
