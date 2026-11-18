/* Theme choice: "system" (follow the OS), "light" or "dark". Stored per browser.
   Loaded in <head> without defer so the page never flashes the wrong theme. */
(function () {
  var KEY = "vmap-theme", root = document.documentElement;
  function read() { try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; } }
  function apply(t) {
    if (t === "light" || t === "dark") root.setAttribute("data-theme", t); else root.removeAttribute("data-theme");
    document.querySelectorAll("[data-theme-set]").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-theme-set") === t ? "true" : "false");
    });
  }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    apply(read());
    document.querySelectorAll("[data-theme-set]").forEach(function (b) {
      b.addEventListener("click", function () {
        var t = b.getAttribute("data-theme-set");
        try { localStorage.setItem(KEY, t); } catch (e) {}
        apply(t);
      });
    });
  });
})();
