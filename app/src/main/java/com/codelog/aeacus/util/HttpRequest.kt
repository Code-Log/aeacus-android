package com.codelog.aeacus.util

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.io.*
import java.net.HttpURLConnection
import java.net.URL

class HttpRequest(url: String, body: JsonObject) {
    private val url: URL
    private val body: JsonObject
    var responseCode: Int
    private var sent: Boolean
    var response: JsonObject?

    init {
        this.url = URL(url)
        this.body = body
        this.responseCode = -1
        sent = false
        response = null
    }

    fun sendRequest() {
        if (sent)
            return

        val connection = url.openConnection() as HttpURLConnection
        connection.setRequestProperty("Content-Type", "application/json")

        val strBody = body.toString().replace("\\/", "/")
        connection.doOutput = true
        val writer = BufferedWriter(OutputStreamWriter(connection.outputStream))
        writer.write(strBody)
        writer.flush()
        writer.close()

        responseCode = connection.responseCode
        sent = true

        val builder = StringBuilder()
        val reader = BufferedReader(InputStreamReader(connection.inputStream))
        var line = reader.readLine()
        while (line != null) {
            builder.append(line)
            line = reader.readLine()
        }

        response = JsonParser.parseString(builder.toString()).asJsonObject
        connection.disconnect()
    }
}