/*
 * Runs in <head> before first paint so the saved / preferred theme is applied
 * without a light-to-dark flash. Kept tiny and dependency-free.
 */
(function () {
  'use strict';
  var theme = null;
  try { theme = JSON.parse(localStorage.getItem('thqv.theme')); } catch (e) { /* storage unavailable or bad JSON */ }
  if (theme == null) {
    try { theme = localStorage.getItem('theme'); } catch (e) { /* earlier versions stored the raw string here */ }
  }
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', theme);
})();
