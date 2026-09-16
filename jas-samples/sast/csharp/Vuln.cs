// JAS SAST demo fixture (C#). Not built or referenced by any project.
//
// Findings demonstrated:
//  - CWE-89 / OWASP A03:2021 Injection: SQL injection via SqlCommand text
//    concatenation (High).
//  - CWE-502 Deserialization of untrusted data: BinaryFormatter used on
//    an untrusted stream (Medium).

using System;
using System.Data.SqlClient;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace JasSamples
{
    public class Vuln
    {
        public void LookupUser(SqlConnection conn, string userSuppliedUsername)
        {
            // Vulnerable: untrusted input concatenated directly into SQL text.
            string query = "SELECT * FROM Users WHERE Username = '" + userSuppliedUsername + "'";
            var command = new SqlCommand(query, conn);
            command.ExecuteReader();
        }

        public object LoadSessionBlob(Stream untrustedInput)
        {
            // Vulnerable: BinaryFormatter can execute arbitrary code during
            // deserialization of attacker-controlled bytes.
            var formatter = new BinaryFormatter();
            return formatter.Deserialize(untrustedInput);
        }
    }
}
