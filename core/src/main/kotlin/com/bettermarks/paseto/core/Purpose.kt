package com.bettermarks.paseto.core

enum class Purpose(val purpose: String) {
  Local("local"),
  Public("public");

  companion object {
    val byName = entries.associateBy { it.purpose }
  }
}
