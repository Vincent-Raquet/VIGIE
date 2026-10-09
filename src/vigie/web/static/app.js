/* Vigie — seul script de l'application (la CSP interdit tout script inline).
   Thème clair/sombre mémorisé dans le navigateur ; le reste est servi par htmx. */
(function () {
  "use strict";
  var root = document.documentElement;
  try {
    var saved = window.localStorage.getItem("vigie-theme");
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  } catch (e) { /* stockage indisponible : thème du système */ }
  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-theme-toggle]");
    if (!button) return;
    var dark = root.getAttribute("data-theme") === "dark" ||
      (!root.getAttribute("data-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches);
    var next = dark ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { window.localStorage.setItem("vigie-theme", next); } catch (e) { /* ignoré */ }
  });
})();
