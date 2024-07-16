package com.bettermarks.paseto.core

enum class Version(val version: String) {
  V1("v1"),
  V2("v2"),
  V3("v3"),
  V4("v4");

  companion object {
    val byName = entries.associateBy { it.version }
  }
}
