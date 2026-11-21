// Build-time highlighting for ```json blocks. A tokenizer, not a parser: it marks keys, strings, numbers,
// literals and punctuation, and passes anything else through as plain text, so a block that is not strict
// JSON (an ellipsis, a comment) still renders. Its one promise: the highlighted block's text content is
// exactly the source text (tested).

import { esc } from "./html.mjs";

const TOKEN = /("(?:[^"\\\n]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}[\],:])|(\s+)|([^"\s{}[\],:\d-]+|[\s\S])/gy;

/** HTML for a JSON code block's content: spans with classes j-k (key), j-s, j-n, j-l (literal), j-p. */
export function highlightJson(text) {
  let out = "";
  TOKEN.lastIndex = 0;
  let m;
  while (TOKEN.lastIndex < text.length && (m = TOKEN.exec(text))) {
    const [all, str, num, lit, pun, ws] = m;
    if (str !== undefined) {
      const rest = text.slice(TOKEN.lastIndex);
      const isKey = /^\s*:/.test(rest);
      out += `<span class="${isKey ? "j-k" : "j-s"}">${esc(str)}</span>`;
    } else if (num !== undefined) out += `<span class="j-n">${esc(num)}</span>`;
    else if (lit !== undefined) out += `<span class="j-l">${lit}</span>`;
    else if (pun !== undefined) out += `<span class="j-p">${esc(pun)}</span>`;
    else if (ws !== undefined) out += ws;
    else out += esc(all);
  }
  return out;
}
