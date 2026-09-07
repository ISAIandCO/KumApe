(async () => {
  "use strict";
  if (globalThis.__kumapeNativeSearch) return;
  globalThis.__kumapeNativeSearch = true;

  function banner(text, query, success = false) {
    document.getElementById("kumape-native-search")?.remove();
    const root = document.createElement("div"); root.id = "kumape-native-search";
    Object.assign(root.style, { position: "fixed", zIndex: "2147483647", top: "12px", left: "50%", transform: "translateX(-50%)", maxWidth: "760px", padding: "10px 12px", borderRadius: "8px", boxShadow: "0 5px 24px #0006", color: "#fff", background: success ? "#177a55" : "#7a4f17", font: "13px/1.4 system-ui,sans-serif" });
    const label = document.createElement("span"); label.textContent = text;
    const copy = document.createElement("button"); copy.type = "button"; copy.textContent = "Копировать SQL";
    Object.assign(copy.style, { marginLeft: "10px", padding: "4px 8px", cursor: "pointer" });
    copy.addEventListener("click", async () => { await navigator.clipboard.writeText(query); label.textContent = "SQL скопирован. Вставьте его в строку поиска KUMA."; });
    const close = document.createElement("button"); close.type = "button"; close.textContent = "×";
    Object.assign(close.style, { marginLeft: "8px", border: "0", background: "transparent", color: "inherit", fontSize: "18px", cursor: "pointer" });
    close.addEventListener("click", () => root.remove()); root.append(label, copy, close); document.documentElement.append(root);
  }

  function visible(element) {
    const rect = element.getBoundingClientRect(); const style = getComputedStyle(element);
    return rect.width > 40 && rect.height > 12 && style.visibility !== "hidden" && style.display !== "none";
  }

  function editorScore(element) {
    const context = `${element.getAttribute("placeholder") || ""} ${element.getAttribute("aria-label") || ""} ${element.closest("form,section,main,div")?.textContent?.slice(0, 500) || ""}`.toLowerCase();
    let score = visible(element) ? 10 : -100;
    if (/sql|запрос|query/.test(context)) score += 20;
    if (element.matches("textarea")) score += 8;
    if (element.closest(".monaco-editor,.CodeMirror,.cm-editor")) score += 15;
    if (/поиск по полям|search fields/.test(context)) score -= 10;
    return score;
  }

  function setEditorValue(editor, query) {
    editor.focus();
    if (editor instanceof HTMLTextAreaElement || editor instanceof HTMLInputElement) {
      const prototype = editor instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(prototype, "value")?.set?.call(editor, query);
    } else {
      editor.textContent = query;
    }
    editor.dispatchEvent(new InputEvent("beforeinput", { bubbles: true, inputType: "insertText", data: query }));
    editor.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: query }));
    editor.dispatchEvent(new Event("change", { bubbles: true }));
    return String(editor.value ?? editor.textContent ?? "").includes("SELECT");
  }

  function findRunButton(editor) {
    const roots = [editor.closest("form"), editor.closest("section"), editor.parentElement, document];
    for (const root of roots) {
      if (!root) continue;
      const match = [...root.querySelectorAll("button,[role=button]")].find((button) => visible(button) && /^(найти|поиск|выполнить|запустить|search|run)(\s|$)/i.test(button.textContent.trim()) && !button.disabled);
      if (match) return match;
    }
    return null;
  }

  try {
    const response = await browser.runtime.sendMessage({ type: "native-search:claim" });
    if (!response?.ok) throw new Error(response?.error || "Не удалось получить SQL");
    const query = response.request.query;
    const period = response.request.period;
    const periodHint = period?.from && period?.to ? ` Период: ${period.from} — ${period.to}; проверьте его в селекторе времени KUMA.` : "";
    let applied = false;
    for (let attempt = 0; attempt < 40 && !applied; attempt += 1) {
      const candidates = [...document.querySelectorAll("textarea,input[type=text],[contenteditable=true]")].sort((a, b) => editorScore(b) - editorScore(a));
      const editor = candidates.find((candidate) => editorScore(candidate) > 15);
      if (editor && setEditorValue(editor, query)) {
        const run = findRunButton(editor);
        if (run) { run.click(); applied = true; }
      }
      if (!applied) await new Promise((resolve) => setTimeout(resolve, 250));
    }
    banner((applied ? "KumApe подставил SQL в поиск событий KUMA и запустил его." : "KumApe открыл раздел событий, но не распознал редактор этой сборки KUMA.") + periodHint, query, applied);
    await browser.runtime.sendMessage({ type: "native-search:report", applied });
  } catch (error) {
    banner(`KumApe: ${error.message}`, "");
  }
})();
