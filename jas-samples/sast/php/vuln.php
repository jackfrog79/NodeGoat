<?php
/*
 * JAS SAST demo fixture (PHP). Not included/required anywhere.
 *
 * Findings demonstrated:
 *  - CWE-90 LDAP injection: unsanitized input in an LDAP search filter
 *    (Medium).
 *  - CWE-89 / OWASP A03:2021 Injection: SQL injection via mysqli string
 *    concatenation (High).
 */

function findLdapUser($ldapConn, $userSuppliedName) {
    // Vulnerable: user input concatenated directly into an LDAP filter,
    // allowing filter-injection to bypass search scope/auth checks.
    $filter = "(&(objectClass=user)(uid=" . $userSuppliedName . "))";
    return ldap_search($ldapConn, "dc=example,dc=com", $filter);
}

function findAccountByUsername($mysqli, $userSuppliedUsername) {
    // Vulnerable: untrusted input concatenated directly into SQL text
    // instead of using a prepared statement.
    $query = "SELECT * FROM accounts WHERE username = '" . $userSuppliedUsername . "'";
    return mysqli_query($mysqli, $query);
}
