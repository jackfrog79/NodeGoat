/*
 * JAS SAST demo fixture (C++). Not built or linked into anything.
 *
 * Findings demonstrated:
 *  - CWE-89 / OWASP A03:2021 Injection: SQL injection via string
 *    concatenation into a query (High).
 *  - CWE-798 Use of hard-coded credentials: DB password literal in source
 *    (Low/Medium).
 */
#include <string>
#include <sqlite3.h>

static const char *DB_PASSWORD = "SuperSecretP@ss123"; // Vulnerable: hardcoded credential

std::string build_lookup_query(const std::string &userSuppliedUsername) {
    // Vulnerable: untrusted input concatenated directly into SQL text.
    return "SELECT * FROM accounts WHERE username = '" + userSuppliedUsername + "'";
}

int lookup_account(sqlite3 *db, const std::string &username) {
    std::string query = build_lookup_query(username);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc;
}
