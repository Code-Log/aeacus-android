package com.codelog.aeacus

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.codelog.aeacus.api.Message
import com.codelog.aeacus.api.Payload
import com.codelog.aeacus.api.UserContext
import com.codelog.aeacus.crypto.Crypto
import com.codelog.aeacus.databinding.FragmentSecondBinding
import com.google.gson.JsonObject
import java.io.File
import java.nio.file.Files
import java.time.Instant
import java.util.*

/**
 * A simple [Fragment] subclass as the second destination in the navigation.
 */
class SecondFragment : Fragment() {

    private var _binding: FragmentSecondBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater, container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {

        _binding = FragmentSecondBinding.inflate(inflater, container, false)
        return binding.root

    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnShutdownCommand.setOnClickListener {
            val payload = object : Payload(1, Date.from(Instant.now()).time, "command") {
                override fun serialize(): JsonObject {
                    val json = JsonObject()
                    json.addProperty("command", "shutdown")
                    json.addProperty("target", target)
                    json.addProperty("timestamp", timestamp)
                    json.addProperty("type", type)
                    return json
                }
            }

            val sig = Crypto.signPayload(
                payload,
                UserContext.currentUser?.secretKey ?: throw Exception("No logged in user!"),
                UserContext.currentUser?.vaultKey ?: throw Exception("No logged in user!")
            )

            val handler = Handler(Looper.myLooper()!!)

            val msg = Message(payload, sig, UserContext.currentUser?.username ?: throw Exception("No logged in user!"))
            UserContext.sendMessage(msg) { error ->
                if (error != null) {
                    handler.post {
                        Toast.makeText(context, error, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}