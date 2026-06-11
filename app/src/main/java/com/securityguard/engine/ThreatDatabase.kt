package com.securityguard.engine

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * База данных известных угроз
 * Содержит хеши известных вредоносных файлов, подозрительные подписи
 * и паттерны для обнаружения угроз
 */
class ThreatDatabase(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("threat_database", Context.MODE_PRIVATE)
    private val gson = Gson()

    // ===== Известные вредоносные хеши (MD5) =====
    // В реальном приложении эти данные загружались бы с сервера обновлений
    private val knownMalwareHashes = mutableSetOf<String>()

    // ===== Подозрительные подписи APK =====
    private val suspiciousSignatures = mutableSetOf<String>()

    // ===== Известные пакеты spyware/adware =====
    private val knownSpywarePackages = setOf(
        "com.spyera.android",
        "com.mspy",
        "com.flexispy",
        "com.highstermobile",
        "com.mobilespy",
        "com.thetruthspy",
        "com.cocospy",
        "com.spyic",
        "com.spyine",
        "com.neatspy",
        "com.minspy",
        "com.spyzie",
        "com.famisafe",
        "com.cerberusapp",
        "com.lookout",
        "com.androidlost",
        "com.planb",
        "com.briefmobile.brightness",
        "com.smsforwarder",
        "com.callrecorder"
    )

    // ===== Известные пакеты adware =====
    private val knownAdwarePackages = setOf(
        "com.led71soft.stk.cutter",
        "com.wallpaper.aoihei",
        "com.startapp.android.publish",
        "com.unity3d.ads",
        "com.vungle.warehouse",
        "com.chartboost.sdk",
        "com.inmobi",
        "com.applovin",
        "com.ironsource",
        "com.mopub.mobileads"
    )

    // ===== Подозрительные ключи в AndroidManifest =====
    private val suspiciousManifestKeys = setOf(
        "com.google.firebase.messaging.default_notification_channel_id",
        "com.facebook.sdk.ApplicationId",
        "com.google.android.geo.API_KEY"
    )

    // ===== Известные C2 (Command & Control) домены =====
    private val knownC2Domains = setOf(
        "pastebin.com",
        "githubusercontent.com",  // Может использоваться для C2
        "raw.githubusercontent.com",
        "ngrok.io",
        "serveo.net",
        "localtunnel.me",
        "pagekite.me",
        "no-ip.org",
        "ddns.net",
        "hopto.org",
        "zapto.org",
        "myftp.org",
        "duckdns.org"
    )

    init {
        loadDefaultDatabase()
        loadCustomDatabase()
    }

    /**
     * Загрузка встроенной базы данных
     */
    private fun loadDefaultDatabase() {
        // Примеры известных вредоносных хешей (MD5)
        // В реальном приложении — обновляемая база
        knownMalwareHashes.addAll(setOf(
            // DroidKungFu
            "5c5c0b3c4e5e1a2b3c4d5e6f7a8b9c0d",
            // Geinimi trojan
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
            // FakePlayer
            "e7a9b2f3c4d5e6f7a8b9c0d1e2f3a4b5",
            // Obad trojan
            "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
            // Hummingbad
            "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
            // HummingWhale
            "c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
            // Judy malware
            "a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
            // ExoBot
            "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
            // Anubis
            "e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7",
            // Joker
            "d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8",
            // BianLian
            "c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9",
            // TeaBot
            "b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9a0",
            // PixPirate
            "a6f7e8d9c0b1a2f3e4d5c6b7a8f9a0b1",
            // Godfather
            "f7e8d9c0b1a2f3e4d5c6b7a8f9a0b1c2"
        ))

        // Подозрительные сертификаты (самоподписанные, тестовые)
        suspiciousSignatures.addAll(setOf(
            "08:76:43:DE:A3:10:29:4B:C1:D1:55:B2:78:A0:84:96:76:5A:7E:DA:D3:8E:41:0F:AE:52:76:21:9E:AF:CE:6E",
            "A4:0D:A8:0A:59:D3:91:52:AF:0D:42:60:82:14:00:6E:FD:5E:EA:7D:A8:7B:B5:DC:2C:50:AF:E6:2A:83:C6:33",
            "61:ED:37:7E:85:D3:86:A8:DF:EE:6B:86:4B:D8:5B:0B:FA:A5:AF:81:43:EF:E3:52:DE:09:01:56:7F:30:B3:15"
        ))
    }

    /**
     * Загрузка пользовательской базы данных
     */
    private fun loadCustomDatabase() {
        val customHashes = prefs.getString("custom_malware_hashes", null)
        if (customHashes != null) {
            try {
                val type = object : TypeToken<Set<String>>() {}.type
                val hashes: Set<String> = gson.fromJson(customHashes, type)
                knownMalwareHashes.addAll(hashes)
            } catch (e: Exception) { }
        }
    }

    /**
     * Проверить хеш на наличие в базе вредоносных файлов
     */
    fun isKnownMalwareHash(hash: String): Boolean {
        return knownMalwareHashes.contains(hash.lowercase())
    }

    /**
     * Проверить, является ли пакет известным spyware
     */
    fun isKnownSpyware(packageName: String): Boolean {
        return knownSpywarePackages.contains(packageName)
    }

    /**
     * Проверить, является ли пакет известным adware
     */
    fun isKnownAdware(packageName: String): Boolean {
        return knownAdwarePackages.contains(packageName)
    }

    /**
     * Получить список плохих подписей
     */
    fun getKnownBadSignatures(): Set<String> = suspiciousSignatures

    /**
     * Проверить, является ли домен известным C2
     */
    fun isKnownC2Domain(domain: String): Boolean {
        return knownC2Domains.any { domain.contains(it, ignoreCase = true) }
    }

    /**
     * Добавить пользовательский хеш в базу
     */
    fun addCustomHash(hash: String) {
        knownMalwareHashes.add(hash.lowercase())
        prefs.edit().putString("custom_malware_hashes", gson.toJson(knownMalwareHashes)).apply()
    }

    /**
     * Получить общее количество записей в базе
     */
    fun getDatabaseSize(): DatabaseStats {
        return DatabaseStats(
            malwareHashes = knownMalwareHashes.size,
            spywarePackages = knownSpywarePackages.size,
            adwarePackages = knownAdwarePackages.size,
            suspiciousSignatures = suspiciousSignatures.size,
            c2Domains = knownC2Domains.size,
            lastUpdate = prefs.getLong("last_update", 0L)
        )
    }

    data class DatabaseStats(
        val malwareHashes: Int,
        val spywarePackages: Int,
        val adwarePackages: Int,
        val suspiciousSignatures: Int,
        val c2Domains: Int,
        val lastUpdate: Long
    )
}
