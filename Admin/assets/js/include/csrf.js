/**
 * csrf.js
 * --------
 * Fix for V-02 (Absence of Anti-CSRF Tokens).
 *
 * Rather than hand-editing every $.ajax() call across add.js / homejs.js /
 * main.js / delete.js / upload.js (which build their POST bodies as either
 * a FormData object or a plain {field: value} object), a single jQuery
 * ajaxPrefilter attaches the current session's CSRF token to every POST
 * request automatically, right before jQuery serialises it. server/api.php
 * validates it with require_csrf_token() for every state-changing action.
 */
(function ($) {
  if (!$ || !$.ajaxPrefilter) {
    return;
  }

  $.ajaxPrefilter(function (options) {
    if ((options.type || "GET").toUpperCase() !== "POST") {
      return;
    }

    var tokenMeta = document.querySelector('meta[name="csrf-token"]');
    var token = tokenMeta ? tokenMeta.getAttribute("content") : "";
    if (!token) {
      return;
    }

    if (options.data instanceof FormData) {
      options.data.append("csrf_token", token);
    } else if (typeof options.data === "object" && options.data !== null) {
      options.data.csrf_token = token;
    } else if (typeof options.data === "string") {
      options.data +=
        (options.data.length ? "&" : "") +
        "csrf_token=" +
        encodeURIComponent(token);
    } else {
      options.data = { csrf_token: token };
    }
  });
})(window.jQuery);
