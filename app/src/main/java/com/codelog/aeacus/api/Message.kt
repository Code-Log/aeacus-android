package com.codelog.aeacus.api

import com.google.gson.JsonObject

open class Payload(val target: Int, val timestamp: Long, val type: String) {
    open fun serialize(): JsonObject {
        val json = JsonObject()
        json.addProperty("target", target)
        json.addProperty("timestamp", timestamp)
        json.addProperty("type", type)
        return json
    }
}

data class Message(val payload: Payload, val signature: String, val user: String) {
    fun serialize(): JsonObject {
        val json = JsonObject()
        json.add("payload", payload.serialize())
        json.addProperty("signature", signature)
        json.addProperty("user", user)
        return json
    }
}