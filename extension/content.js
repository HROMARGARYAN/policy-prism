
let activeMarks = [];
function clearHighlights() {
  for (const el of activeMarks) {
    el.outerHTML = el.innerText;
  }
  activeMarks = [];
}

function highlightPhrases(phrases) {
  clearHighlights();
  if (!phrases || !phrases.length) return;
  const root = document.querySelector('main') || document.querySelector('article') || document.body;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null, false);
  let node;
  const normalized = phrases.filter(Boolean).map(p => p.trim()).filter(p => p.length > 6);
  while (node = walker.nextNode()) {
    const text = node.nodeValue;
    let replaced = text;
    for (const p of normalized) {
      const safe = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(safe, 'i');
      if (re.test(replaced)) {
        replaced = replaced.replace(re, (m) => `<<<PT_MARK>>>${m}<<<PT_MARK_END>>>`);
      }
    }
    if (replaced !== text) {
      const span = document.createElement('span');
      span.innerHTML = replaced
        .replaceAll('<<<PT_MARK>>>', '<mark class="pt-highlight">')
        .replaceAll('<<<PT_MARK_END>>>', '</mark>');
      node.parentNode.replaceChild(span, node);
      activeMarks.push(...span.querySelectorAll('mark.pt-highlight'));
    }
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.cmd === 'highlightPhrases') highlightPhrases(msg.payload);
  if (msg.cmd === 'clearHighlights') clearHighlights();
});
