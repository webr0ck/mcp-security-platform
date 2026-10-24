// Small, vanilla, additive-only progressive enhancement.
// Every form this file touches already works with JS disabled — it just
// posts. This only adds a confirmation step for destructive actions.
(function () {
  "use strict";

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    var message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
