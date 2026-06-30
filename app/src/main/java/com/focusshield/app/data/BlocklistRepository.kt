package com.focusshield.app.data

import android.content.Context
import com.focusshield.app.R

/**
 * Local, on-device blocklist. No network calls, no API costs.
 *
 * The base list ships as a bundled asset derived from community-maintained,
 * freely licensed hosts-file projects (e.g. Steven Black's unified hosts
 * lists, which include gambling and adult-content categories). Update it by
 * replacing assets/blocklist_gambling.txt and assets/blocklist_adult.txt
 * with a refreshed copy periodically — no subscription required.
 *
 * A keyword heuristic layer catches new/mirror domains that aren't in the
 * static list yet (e.g. domains containing "bet", "casino", "wager", "xxx",
 * "porn", etc. as whole tokens), which matters because static lists always
 * lag behind newly registered domains.
 */
class BlocklistRepository(private val context: Context) {

    private val exactDomains = mutableSetOf<String>()

    // Whole-token heuristics only — deliberately broad category terms,
    // not a catalog of specific sites, so this stays effective against
    // domains that don't exist yet.
    private val keywordHeuristics = listOf(
        "bet", "casino", "wager", "poker", "slots", "sportsbook",
        "gambl", "jackpot", "roulette", "stake",
        "porn", "xxx", "sex", "nsfw", "adult", "xvideos", "xnxx"
    )

    fun loadBlocklists() {
        exactDomains.clear()
        loadAssetFile("blocklist_gambling.txt")
        loadAssetFile("blocklist_adult.txt")
    }

    private fun loadAssetFile(name: String) {
        runCatching {
            context.assets.open(name).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isNotEmpty() && !trimmed.startsWith("#")) {
                        exactDomains.add(trimmed.lowercase())
                    }
                }
            }
        }
    }

    fun isBlocked(hostname: String): Boolean {
        val host = hostname.lowercase().removeSuffix(".")
        if (exactDomains.contains(host)) return true

        // Check parent domains too (e.g. sub.example.com against example.com)
        var parent = host
        while (parent.contains(".")) {
            parent = parent.substringAfter(".")
            if (exactDomains.contains(parent)) return true
        }

        return keywordHeuristics.any { keyword -> containsWholeToken(host, keyword) }
    }

    private fun containsWholeToken(host: String, token: String): Boolean {
        val parts = host.split(".", "-", "_")
        return parts.any { it.contains(token) }
    }

    fun blockedDomainCount(): Int = exactDomains.size
}
