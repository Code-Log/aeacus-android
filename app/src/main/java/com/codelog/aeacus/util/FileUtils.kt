package com.codelog.aeacus.util

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object FileUtils {
    fun writeBinary(file: File, data: ByteArray) {
        val stream = FileOutputStream(file)
        stream.write(data)
        stream.close()
    }

    fun readBinary(file: File): ByteArray {
        val stream = FileInputStream(file)
        val buffer = ArrayList<Char>()
        var ch: Int
        do {
            ch = stream.read()
            buffer.add(ch.toChar())
        } while (ch != -1)

        buffer.removeAt(buffer.size - 1)
        val result = ByteArray(buffer.size)
        var i: Int = 0
        for (char: Char in buffer)
            result[i++] = char.code.toByte()

        return result
    }
}