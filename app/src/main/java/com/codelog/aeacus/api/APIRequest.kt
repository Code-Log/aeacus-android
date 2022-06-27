package com.codelog.aeacus.api

import com.codelog.aeacus.Reference
import com.codelog.aeacus.util.HttpRequest
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.io.IOException

class APIException(message: String) : Exception(message) {
    constructor(response: JsonObject) : this(response.get("message").asString)
}

@FunctionalInterface
interface APIRequestCallback {
    fun callback(res: JsonObject);
}

class APIRequest(method: String, auth: Boolean, vararg params: String) {
    private val method: String
    private val auth: Boolean
    private val params: Array<out String>
    private lateinit var body: JsonObject

    init {
        this.method = method
        this.auth = auth
        this.params = params
    }

    fun send(vararg values: Any): JsonObject {
        if (params.size != values.size)
            throw IllegalArgumentException("Values don't math parameters!")

        body = JsonObject()

        if (auth) {
            val token = UserContext.currentUser?.token ?: throw APIException("No logged in user!")
            body.addProperty("token", token.token)
            body.addProperty("signature", token.signature)
        }
        for (i in params.indices) {
            val v = values[i]
            when (v) {
                is JsonElement -> body.add(params[i], v)
                is String -> body.addProperty(params[i], v)
                is Char -> body.addProperty(params[i], v)
                is Boolean -> body.addProperty(params[i], v)
                is Number -> body.addProperty(params[i], v)
                else -> throw IllegalArgumentException("Parameter $i is not of compatible type!")
            }
        }

        val req = HttpRequest(Reference.API_URL + method, body)

        try {
            req.sendRequest()
        } catch (e: IOException) {
            throw APIException(e.message ?: "")
        }

        val res = req.response ?: throw IOException("No response received from server!")
        if (!req.response?.get("status")?.asString.equals("ok"))
            throw APIException(res)

        return res
    }

    fun sendAsync(cb: (res: JsonObject) -> Unit, vararg values: Any) {
        val thread = Thread {
            if (params.size != values.size)
                throw IllegalArgumentException("Values don't math parameters!")

            body = JsonObject()

            if (auth) {
                val token = UserContext.currentUser?.token ?: throw APIException("No logged in user!")
                body.addProperty("token", token.token)
                body.addProperty("signature", token.signature)
            }
            for (i in params.indices) {
                when (val v = values[i]) {
                    is JsonElement -> body.add(params[i], v)
                    is String -> body.addProperty(params[i], v)
                    is Char -> body.addProperty(params[i], v)
                    is Boolean -> body.addProperty(params[i], v)
                    is Number -> body.addProperty(params[i], v)
                    else -> throw IllegalArgumentException("Parameter $i is not of compatible type!")
                }
            }

            val req = HttpRequest(Reference.API_URL + method, body)

            try {
                req.sendRequest()
            } catch (e: IOException) {
                throw APIException(e.message ?: "")
            }

            val res = req.response ?: throw IOException("No response received from server!")
            cb(res)
        }
        thread.start()
    }
}