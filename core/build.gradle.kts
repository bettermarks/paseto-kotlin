/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Kotlin library project to get you started.
 * For more details on building Java & JVM projects, please refer to https://docs.gradle.org/8.9/userguide/building_java_projects.html in the Gradle documentation.
 */

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("com.ncorti.ktfmt.gradle")

    `java-library`
    `maven-publish`
}

group = "com.github.bettermarks"
version = "0.1.0"

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "paseto-kotlin-core"
            from(components["java"])
            pom {
                licenses {
                    license {
                        name = "MIT License"
                        url = "https://opensource.org/licenses/MIT"
                    }
                }
                scm {
                    url = "https://github.com/BetterMarks/paseto-kotlin"
                }
            }
        }
    }
}

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    implementation(libs.bouncycastle.bcprov)

    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(libs.junit.jupiter.engine)
    testImplementation(libs.junit.jupiter.params)
    testImplementation(libs.bouncycastle.bcpkix)
    testImplementation(kotlin("test"))
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
    withJavadocJar()
    withSourcesJar()
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
