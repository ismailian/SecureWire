// SecureWire site: mobile nav, OS-aware download button, docs TOC highlight, gentle reveal.
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  // Mobile navigation
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    nav.addEventListener("click", function (e) {
      if (e.target.closest("a")) {
        nav.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // Detect the visitor's OS to point the main button at the right package.
  function detectOs() {
    var p = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "").toLowerCase();
    var ua = navigator.userAgent.toLowerCase();
    if (/android|iphone|ipad/.test(ua)) return null;
    if (p.indexOf("win") === 0 || ua.indexOf("windows") !== -1) return "windows";
    if (p.indexOf("mac") === 0 || ua.indexOf("mac os") !== -1) return "macos";
    if (p.indexOf("linux") !== -1 || ua.indexOf("linux") !== -1) return "linux";
    return null;
  }
  var os = detectOs();
  var labels = { windows: "Download for Windows", macos: "Download for macOS", linux: "Download for Linux" };
  if (os) {
    document.querySelectorAll("[data-os-download]").forEach(function (a) {
      var card = document.getElementById("dl-" + os);
      var first = card && card.querySelector(".files a");
      if (first) {
        a.href = first.href;
        var label = a.querySelector("[data-label]");
        if (label) label.textContent = labels[os];
      }
    });
    var rec = document.getElementById("dl-" + os);
    if (rec) rec.classList.add("recommended");
  }

  // Reveal sections once as they scroll into view.
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var items = document.querySelectorAll(".reveal");
  if (!reduce && "IntersectionObserver" in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.classList.add("in");
          io.unobserve(en.target);
        }
      });
    }, { rootMargin: "0px 0px -8% 0px" });
    items.forEach(function (el) { io.observe(el); });
  } else {
    items.forEach(function (el) { el.classList.add("in"); });
  }

  // Docs: highlight the current section in the table of contents.
  var toc = document.querySelectorAll(".toc a[href^='#']");
  if (toc.length && "IntersectionObserver" in window) {
    var map = {};
    toc.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var current = null;
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting && map[en.target.id]) {
          if (current) current.classList.remove("active");
          current = map[en.target.id];
          current.classList.add("active");
        }
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    Object.keys(map).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) spy.observe(el);
    });
  }

  var y = document.getElementById("year");
  if (y) y.textContent = String(new Date().getFullYear());
})();
