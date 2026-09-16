// JAS SAST demo fixture (Kotlin/Android). Not part of any Android module/build.
//
// Findings demonstrated (paired with AndroidManifest.xml in this folder):
//  - CWE-926 Improper export of Android component: an exported Activity
//    with no permission requirement, reachable by any app on the device
//    (Medium/High).
//  - CWE-926 Mutable implicit PendingIntent: allows another app to hijack
//    the Intent's action/extras (Medium).

package com.jasdemo.vuln

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle

class VulnActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val userId = intent.getStringExtra("userId")
        // Vulnerable: this Activity is declared android:exported="true" with
        // no permission in the manifest, so any installed app can launch it
        // and control the "userId" extra.
        loadAccountFor(userId)
    }

    private fun loadAccountFor(userId: String?) {
        // ... account loading omitted for brevity ...
    }

    private fun buildCallbackIntent(): PendingIntent {
        val intent = Intent("com.jasdemo.vuln.ACTION_CALLBACK")
        // Vulnerable: implicit Intent wrapped in a mutable PendingIntent with
        // no FLAG_IMMUTABLE — a malicious app can modify the Intent before
        // it's delivered.
        return PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
    }
}
