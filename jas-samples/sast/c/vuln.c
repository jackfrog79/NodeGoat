/*
 * JAS SAST demo fixture (C). Not built or linked into anything.
 *
 * Findings demonstrated:
 *  - CWE-78 / OWASP A03:2021 Injection: OS command injection via system()
 *    built from unsanitized user input (High).
 *  - CWE-338 Insecure randomness: rand() used to generate a session token
 *    (Medium).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void run_backup(const char *filename) {
    char cmd[256];
    /* Vulnerable: user-controlled filename concatenated straight into a shell command. */
    snprintf(cmd, sizeof(cmd), "/usr/bin/tar -czf /backups/%s.tar.gz %s", filename, filename);
    system(cmd);
}

int generate_session_token(void) {
    /* Vulnerable: rand() is not cryptographically secure; predictable session tokens. */
    srand((unsigned int)time(NULL));
    return rand();
}

int main(int argc, char **argv) {
    if (argc > 1) {
        run_backup(argv[1]);
        printf("token=%d\n", generate_session_token());
    }
    return 0;
}
