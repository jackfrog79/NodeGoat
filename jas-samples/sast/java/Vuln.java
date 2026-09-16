// JAS SAST demo fixture (Java). Not part of any build (no build file references it).
//
// Findings demonstrated:
//  - CWE-611 / OWASP A05:2021 Security Misconfiguration: XXE via a
//    DocumentBuilderFactory that has not disabled external entities (Medium).
//  - CWE-502 Deserialization of untrusted data: ObjectInputStream reading
//    attacker-controlled bytes (High).
//  - CWE-798 Use of hard-coded credentials (Low/Medium).

import java.io.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class Vuln {

    private static final String DB_PASSWORD = "adminP@ssw0rd!"; // Vulnerable: hardcoded credential

    // Vulnerable: DocumentBuilderFactory built with default settings allows
    // external entity resolution (XXE), enabling file disclosure / SSRF.
    public Document parseUntrustedXml(InputStream untrustedXml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(untrustedXml);
    }

    // Vulnerable: deserializing an attacker-controlled stream can lead to
    // remote code execution via gadget chains.
    public Object loadSession(InputStream untrustedInput) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(untrustedInput);
        return ois.readObject();
    }
}
