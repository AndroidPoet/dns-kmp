package io.github.androidpoet.dns.sample

import io.github.androidpoet.dns.DnsConfig
import io.github.androidpoet.dns.DnsResolver
import io.github.androidpoet.dns.RecordType
import io.github.androidpoet.dns.Upstreams
import io.github.androidpoet.dns.okhttp.dns
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import okhttp3.Request

fun main(args: Array<String>) =
    runBlocking {
        val name = args.firstOrNull() ?: "example.com"

        DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Cloudflare.https()), dnssec = true)).use { dns ->
            println("DoH, DNSSEC on:")
            val answer = dns.lookup(name, RecordType.A)
            println("  ${answer.security}")
            answer.records.forEach { println("  $it") }
            println("  MX: ${dns.lookup(name, RecordType.MX).records.map { it.data }}")
        }

        DnsResolver(DnsConfig(upstreams = listOf(Upstreams.Quad9.tls()))).use { dns ->
            println("DoT:")
            println("  ${dns.lookupIp(name)}")

            val client = OkHttpClient.Builder().dns(dns).build()
            client.newCall(Request.Builder().url("https://$name/").build()).execute().use { response ->
                println("OkHttp through the resolver: HTTP ${response.code}")
            }
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }
