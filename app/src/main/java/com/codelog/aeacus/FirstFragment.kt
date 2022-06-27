package com.codelog.aeacus

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.codelog.aeacus.api.UserContext
import com.codelog.aeacus.databinding.FragmentFirstBinding
import java.io.File
import java.nio.file.Files

class FirstFragment : Fragment() {
    private var _binding: FragmentFirstBinding? = null

    // This property is only valid between onCreateView and
    // onDestroyView.
    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater, container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View {
        _binding = FragmentFirstBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        if (Files.exists(File(context?.filesDir, "user.bin").toPath())) {
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Authenticate to use Aeacus")
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL).build()

            val executor = ContextCompat.getMainExecutor(context ?: throw Exception())
            val prompt = BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    UserContext.recall()
                    findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
                }

                override fun onAuthenticationFailed() {
                    Toast.makeText(context ?: throw Exception(), "Authentication failed!", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    Toast.makeText(context ?: throw Exception(), "Authentication failed!", Toast.LENGTH_SHORT).show()
                }
            })

            prompt.authenticate(info)
        }

        binding.btnLogin.setOnClickListener {
            val username = binding.txtUname.text.toString()
            val password = binding.txtPassword.text.toString()

            val handler = Handler(Looper.myLooper()!!)

            UserContext.createFromCredentials(username, password) { error ->
                if (error == null) {
                    UserContext.save()
                    handler.post() {
                        findNavController().navigate(R.id.action_FirstFragment_to_SecondFragment)
                    }
                } else {
                    handler.post {
                        Toast.makeText(context, error, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        binding.btnRegister.setOnClickListener {
            val username = binding.txtUname.text.toString()
            val password = binding.txtPassword.text.toString()

            val handler = Handler(Looper.myLooper()!!)

            UserContext.registerNewUser(username, password) { error ->
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