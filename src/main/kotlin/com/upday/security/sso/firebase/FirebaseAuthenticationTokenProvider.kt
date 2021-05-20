package com.upday.security.sso.firebase

import com.google.auth.oauth2.GoogleCredentials
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.upday.security.sso.authentication.SsoAuthenticationToken.PreAuthenticationToken
import com.upday.security.sso.authentication.SsoAuthenticationTokenProvider
import com.upday.security.sso.configuration.SsoProperties
import com.upday.security.sso.configuration.SsoProperties.SsoProvider.Firebase
import org.springframework.stereotype.Component

/**
 * Firebase implementation for [SsoAuthenticationTokenProvider]
 * Uses the private key specified in [SsoProperties.firebase] to initialize a connection to the application's firebase DB
 * If no [SsoProperties.SsoProvider.Firebase.privateKeyFile] is specified, it is looked up in /firebase/private-key.json in the resource folder
 *
 * @author Ido Flasch
 */
@Component
class FirebaseAuthenticationTokenProvider(
    ssoProperties: SsoProperties
) : SsoAuthenticationTokenProvider<String> {

    private lateinit var firebaseAuth: FirebaseAuth

    init {
        if (ssoProperties.firebase?.enabled == true) {
            initializeFirebaseApp(ssoProperties.firebase)
            firebaseAuth = FirebaseAuth.getInstance()
        }
    }

    private fun initializeFirebaseApp(firebase: Firebase) {
        val serviceAccount = javaClass.getResourceAsStream(firebase.privateKeyFile).also {
            if (it == null) throw IllegalStateException("No firebase private key found in ${firebase.privateKeyFile}")
        }

        val options = FirebaseOptions.builder()
            .setCredentials(GoogleCredentials.fromStream(serviceAccount))
            .setDatabaseUrl(firebase.databaseUrl)
            .build()
        try {
            FirebaseApp.getInstance()
        } catch (e: IllegalStateException) {
            FirebaseApp.initializeApp(options)
        }
    }

    override fun createPreAuthenticationToken(
        idToken: String,
        verifyAgainstDb: Boolean
    ): PreAuthenticationToken<String> {
        return firebaseAuth.verifyIdToken(idToken).let { firebaseToken ->
            PreAuthenticationToken(
                firebaseToken.uid,
                firebaseToken,
                verifyAgainstDb = verifyAgainstDb
            )
        }
    }

}

