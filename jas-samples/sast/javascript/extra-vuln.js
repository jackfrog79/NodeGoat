"use strict";

/*
 * JAS SAST demo fixture (JavaScript). Not required/imported anywhere.
 *
 * NodeGoat's real application code (app/routes/report-export.js,
 * app/routes/session.js, app/data/user-dao.js, config/env/all.js) already
 * demonstrates code injection (eval), command injection, path traversal,
 * reflected XSS, weak crypto, hardcoded credentials, and insecure
 * randomness — see the top-level README for the full mapping.
 *
 * This file covers the two SAST categories the real app doesn't otherwise
 * exercise:
 *  - CWE-1333 ReDoS (regex injection / catastrophic backtracking) (Medium).
 *  - CWE-601 / OWASP A01:2021 Open redirect (Low/Medium).
 */

// Vulnerable: catastrophic backtracking on crafted input like
// "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
function isValidEmailLike(userInput) {
    const REDOS_PRONE = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+$/;
    return REDOS_PRONE.test(userInput);
}

// Vulnerable: redirect target taken directly from a query parameter with no
// allowlist/relative-path check, enabling phishing via open redirect.
function handleReturnUrl(req, res) {
    const returnUrl = req.query.returnUrl;
    res.redirect(returnUrl);
}

module.exports = { isValidEmailLike, handleReturnUrl };
