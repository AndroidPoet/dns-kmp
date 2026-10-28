plugins {
    kotlin("jvm")
    application
}

// A minimal consumer: resolve a few names over DoH and DoT, with and without
// DNSSEC, and fetch a page through OkHttp with the resolver plugged in.
// Run: ./gradlew :samples:cli:run --args="example.com"

kotlin { jvmToolchain(17) }

dependencies {
    implementation(project(":dns"))
    implementation(project(":dns-okhttp"))
    implementation(libs.kotlinx.coroutines.core)
}

application {
    mainClass.set("io.github.androidpoet.dns.sample.MainKt")
}
