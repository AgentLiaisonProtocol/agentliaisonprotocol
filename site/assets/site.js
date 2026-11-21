// agentliaisonprotocol.org: conveniences only. Every page is complete without this file.
// No storage and no cookies. The one network request is "Copy page as Markdown", which fetches this page's
// own Markdown mirror from the same site when it is clicked. Built by tools/site (README there); a new
// feature is a further function called from init().
(function () {
  "use strict";

  var WIDE = "(min-width: 960px)";

  function copyText(text, button, done) {
    var original = button.textContent;
    function say(msg) {
      button.textContent = msg;
      button.classList.add("is-done");
      window.setTimeout(function () { button.textContent = original; button.classList.remove("is-done"); }, 1800);
    }
    if (!navigator.clipboard || !navigator.clipboard.writeText) { say("Copy not available"); return; }
    navigator.clipboard.writeText(text).then(function () { say(done); }, function () { say("Copy failed"); });
  }

  // The docs sidebar is a <details> so it collapses on small screens without script; keep it open on wide ones.
  function sidebar() {
    var side = document.querySelector("[data-sidebar]");
    if (!side || !window.matchMedia) return;
    var mq = window.matchMedia(WIDE);
    function apply() {
      if (mq.matches) { side.open = true; side.classList.add("wide-open"); }
      else { side.classList.remove("wide-open"); side.open = false; }
    }
    apply();
    if (mq.addEventListener) mq.addEventListener("change", apply);
    // Bring the current page into view inside the sidebar (the sidebar scrolls on its own on wide screens).
    var cur = side.querySelector('[aria-current="page"]');
    if (cur && mq.matches && side.scrollHeight > side.clientHeight) {
      side.scrollTop = Math.max(0, cur.offsetTop - side.clientHeight / 3);
    }
  }

  // A Copy button on every code block.
  function codeCopy() {
    var blocks = document.querySelectorAll(".prose pre");
    Array.prototype.forEach.call(blocks, function (pre) {
      var wrap = document.createElement("div");
      wrap.className = "code-block";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      var b = document.createElement("button");
      b.type = "button";
      b.className = "copy-code";
      b.textContent = "Copy";
      b.setAttribute("aria-label", "Copy this code");
      b.addEventListener("click", function () { copyText(pre.textContent.replace(/\n$/, ""), b, "Copied"); });
      wrap.appendChild(b);
    });
  }

  // "Copy page as Markdown": fetch the page's Markdown mirror (same site) when clicked. The button stays
  // hidden where that can't work: a page opened from disk, or a browser without fetch or the clipboard.
  function pageCopy() {
    var b = document.querySelector("[data-copy-page]");
    if (!b) return;
    var url = b.getAttribute("data-copy-page");
    if (!url || !/^https?:$/.test(window.location.protocol) || !window.fetch || !navigator.clipboard) return;
    b.hidden = false;
    var original = b.textContent;
    function say(msg) {
      b.textContent = msg;
      b.classList.add("is-done");
      window.setTimeout(function () { b.textContent = original; b.classList.remove("is-done"); }, 1800);
    }
    b.addEventListener("click", function () {
      var text = window.fetch(url, { credentials: "omit" }).then(function (r) {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.text();
      });
      // Where the browser takes a pending value, hand it the fetch, so the copy keeps the click's permission.
      if (window.ClipboardItem && navigator.clipboard.write) {
        var item = new window.ClipboardItem({ "text/plain": text.then(function (t) { return new Blob([t], { type: "text/plain" }); }) });
        navigator.clipboard.write([item]).then(function () { say("Copied the page as Markdown"); }, function () { say("Copy failed"); });
      } else if (navigator.clipboard.writeText) {
        text.then(function (t) { return navigator.clipboard.writeText(t); }).then(function () { say("Copied the page as Markdown"); }, function () { say("Copy failed"); });
      } else say("Copy not available");
    });
  }

  // The outline: filter box (pages with more than 20 headings; "/" focuses it) and the current section.
  function outline() {
    var toc = document.querySelector("[data-toc]");
    if (!toc) return;
    var links = Array.prototype.slice.call(toc.querySelectorAll('a[href^="#"]'));
    var byId = {};
    links.forEach(function (a) { byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a; });

    var box = toc.querySelector(".toc-filter");
    if (box) {
      box.hidden = false;
      var input = box.querySelector("input");
      var empty = toc.querySelector(".toc-empty");
      var items = Array.prototype.slice.call(toc.querySelectorAll(".toc-list li"));
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase();
        var shown = 0;
        items.forEach(function (li) {
          var a = li.querySelector(":scope > a");
          var own = a ? a.textContent.toLowerCase().indexOf(q) !== -1 : false;
          li.dataset.match = own ? "1" : "";
        });
        // A heading stays visible when it or anything under it matches.
        items.slice().reverse().forEach(function (li) {
          var hit = !q || li.dataset.match === "1" || li.querySelector('li:not([hidden])[data-match="1"]') !== null;
          li.hidden = !hit;
          if (hit && li.dataset.match === "1") shown++;
        });
        if (empty) empty.hidden = !q || shown > 0;
      });
      input.addEventListener("keydown", function (e) {
        if (e.key === "Escape") { input.value = ""; input.dispatchEvent(new Event("input")); input.blur(); }
      });
      document.addEventListener("keydown", function (e) {
        if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
        var t = e.target;
        if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
        e.preventDefault();
        var side = document.querySelector("[data-sidebar]");
        if (side && !side.open) side.open = true;
        input.focus();
      });
    }

    if (!("IntersectionObserver" in window)) return;
    var heads = Array.prototype.slice.call(document.querySelectorAll(".prose h2[id], .prose h3[id]")).filter(function (h) { return byId[h.id]; });
    if (!heads.length) return;
    var visible = {};
    var current = null;
    function mark(id) {
      if (id === current) return;
      if (current && byId[current]) byId[current].removeAttribute("aria-current");
      current = id;
      if (id && byId[id]) {
        var a = byId[id];
        a.setAttribute("aria-current", "location");
        var side = document.querySelector("[data-sidebar]");
        if (side && side.scrollHeight > side.clientHeight) {
          var top = a.offsetTop, h = side.clientHeight;
          if (top < side.scrollTop + 40 || top > side.scrollTop + h - 60) side.scrollTop = Math.max(0, top - h / 2);
        }
      }
    }
    // The current section is the last shown heading above the upper third of the window (a heading inside
    // a hidden walkthrough scenario doesn't count).
    function update() {
      var pick = null;
      for (var i = 0; i < heads.length; i++) {
        if (!heads[i].getClientRects().length) continue;
        if (heads[i].getBoundingClientRect().top <= window.innerHeight * 0.3) pick = heads[i].id; else break;
      }
      mark(pick);
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
      update();
    }, { rootMargin: "0px 0px -60% 0px", threshold: [0, 1] });
    heads.forEach(function (h) { io.observe(h); });
    document.addEventListener("wt-change", update);
  }

  // The small-screen menu closes on Escape or a click elsewhere.
  function menu() {
    var m = document.querySelector(".top-menu");
    if (!m) return;
    document.addEventListener("click", function (e) { if (m.open && !m.contains(e.target)) m.open = false; });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape" && m.open) { m.open = false; m.querySelector("summary").focus(); } });
  }


  // The walkthrough: scenario tabs (when there is more than one scenario), one step at a time, Previous and
  // Next, step markers, arrow keys, and a polite live region. Without this every scenario and step stays
  // visible as a list.
  function walkthrough() {
    var root = document.querySelector("[data-wt]");
    if (!root) return;
    var scenarios = Array.prototype.slice.call(root.querySelectorAll("[data-wt-scenario]"));
    var tablist = root.querySelector(".wt-tabs");
    var tabs = Array.prototype.slice.call(root.querySelectorAll(".wt-tab"));
    var controls = root.querySelector(".wt-controls");
    var prev = root.querySelector(".wt-prev");
    var next = root.querySelector(".wt-next");
    var markers = root.querySelector(".wt-markers");
    var live = root.querySelector(".wt-live");
    if (!scenarios.length || !controls || (tablist ? tabs.length !== scenarios.length : scenarios.length !== 1)) return;

    var current = 0;
    var steps = scenarios.map(function (sc) { return Array.prototype.slice.call(sc.querySelectorAll(".wt-step")); });
    var position = scenarios.map(function () { return 0; });

    root.classList.add("wt-js");
    if (tablist) tablist.hidden = false;
    controls.hidden = false;
    // The controls sit right under the current scenario.
    if (tablist) {
      scenarios.forEach(function (sc, i) {
        sc.setAttribute("role", "tabpanel");
        sc.setAttribute("aria-labelledby", tabs[i].id);
        sc.setAttribute("tabindex", "-1");
      });
    }

    function hopMarks(sc, step) {
      var hops = (step.getAttribute("data-hops") || "").split(" ").filter(Boolean);
      var nodes = (step.getAttribute("data-nodes") || "").split(" ").filter(Boolean);
      Array.prototype.forEach.call(sc.querySelectorAll("[data-hop]"), function (g) {
        g.classList.toggle("is-current", hops.indexOf(g.getAttribute("data-hop")) !== -1);
      });
      Array.prototype.forEach.call(sc.querySelectorAll("[data-node]"), function (g) {
        g.classList.toggle("is-active", nodes.indexOf(g.getAttribute("data-node")) !== -1);
      });
    }

    function title(step) {
      var h = step.querySelector(".wt-step-title");
      return h ? h.textContent.replace(/\s+/g, " ").trim() : "";
    }

    function render(announce, animate) {
      var sc = scenarios[current];
      var list = steps[current];
      var k = position[current];
      scenarios.forEach(function (x, i) { x.hidden = i !== current; });
      tabs.forEach(function (t, i) {
        t.setAttribute("aria-selected", i === current ? "true" : "false");
        t.tabIndex = i === current ? 0 : -1;
      });
      list.forEach(function (st, i) {
        st.hidden = i !== k;
        st.classList.remove("is-entering");
      });
      if (animate) {
        void list[k].offsetWidth;
        list[k].classList.add("is-entering");
      }
      sc.parentNode.insertBefore(controls, sc.nextSibling);
      markers.textContent = "";
      list.forEach(function (st, i) {
        var li = document.createElement("li");
        var b = document.createElement("button");
        b.type = "button";
        b.textContent = String(i + 1);
        b.setAttribute("aria-label", "Step " + (i + 1) + ": " + title(st).replace(/^Step \d+ of \d+\.\s*/, ""));
        if (i === k) b.setAttribute("aria-current", "step");
        b.addEventListener("click", function () { go(i, true); });
        li.appendChild(b);
        markers.appendChild(li);
      });
      document.dispatchEvent(new Event("wt-change"));
      prev.disabled = k === 0;
      next.disabled = k === list.length - 1;
      hopMarks(sc, list[k]);
      if (announce) live.textContent = title(list[k]);
    }

    function go(k, focusStep) {
      var list = steps[current];
      if (k < 0 || k >= list.length || k === position[current]) return;
      position[current] = k;
      render(true, true);
      if (focusStep) {
        var h = list[k].querySelector(".wt-step-title");
        if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: true }); }
      }
    }

    function select(i, focusTab) {
      if (i < 0 || i >= scenarios.length) return;
      current = i;
      render(true, false);
      if (focusTab) tabs[i].focus();
    }

    prev.addEventListener("click", function () { go(position[current] - 1, false); });
    next.addEventListener("click", function () { go(position[current] + 1, false); });
    tabs.forEach(function (t, i) { t.addEventListener("click", function () { select(i, false); }); });
    if (tablist) tablist.addEventListener("keydown", function (e) {
      var i = tabs.indexOf(document.activeElement);
      if (i === -1) return;
      var to = e.key === "ArrowRight" ? i + 1 : e.key === "ArrowLeft" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? tabs.length - 1 : null;
      if (to === null) return;
      e.preventDefault();
      select((to + tabs.length) % tabs.length, true);
    });
    // Left and right arrows step through the current scenario while focus is inside it or on its controls.
    root.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      if (e.altKey || e.ctrlKey || e.metaKey || (tablist && tablist.contains(e.target))) return;
      var t = e.target;
      if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
      e.preventDefault();
      go(position[current] + (e.key === "ArrowRight" ? 1 : -1), false);
    });
    // A link to a scenario (#wt-meeting, or its title #wt-meeting-title) or to a step (#wt-meeting-3) opens
    // that scenario at that step, when the page loads and when the link is followed on the page.
    function fromHash() {
      var hash = decodeURIComponent((location.hash || "").slice(1));
      var found = false;
      scenarios.forEach(function (sc, i) {
        if (hash === sc.id || hash === sc.id + "-title") { current = i; found = true; }
        steps[i].forEach(function (st, k) { if (st.id === hash) { current = i; position[i] = k; found = true; } });
      });
      return found;
    }
    fromHash();
    render(false, false);
    window.addEventListener("hashchange", function () {
      if (!fromHash()) return;
      render(true, false);
      var el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (el) el.scrollIntoView();
    });
  }

  function init() {
    sidebar();
    codeCopy();
    pageCopy();
    outline();
    menu();
    walkthrough();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
