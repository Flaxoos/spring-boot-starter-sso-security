package com.upday.security.sso.configuration

import com.upday.security.sso.configuration.SsoProperties.SsoProvider.Firebase
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.ConstructorBinding
import org.springframework.security.web.util.matcher.RequestMatcher
import javax.servlet.http.HttpServletRequest

/**
 * Picks up properties defined in the application configuration and binds them to this class
 * The definition of these properties is defined in META-INF/spring-configuration-metadata.json
 *
 * @property authenticatedAntPatterns
 * @property authenticatedRequests
 * @property disableForAntPatterns
 * @property disableForRequests
 * @property unauthenticatedAntPatterns
 * @property unauthenticatedRequests
 * @property firebase
 * @constructor Create empty Sso properties
 *
 * @author Ido Flasch
 */
@ConfigurationProperties("sso")
@ConstructorBinding
data class SsoProperties(
    /**
     * Http methods and ant patterns that will be checked against the db to check if the user exists
     */
    val authenticatedAntPatterns: List<String> = emptyList(),
    /**
     * Requests that will be checked against the db to check if the user exists
     */
    val authenticatedRequests: List<Request> = emptyList(),
    /**
     * Http methods and ant patterns that the sso filter will ignore, meaning, the security id token won't be looked up and no authentication will be applied
     */
    val disableForAntPatterns: List<String> = emptyList(),
    /**
     * Requests that the sso filter will ignore, meaning, the security id token won't be looked up and no authentication will be applied
     */
    val disableForRequests: List<Request> = emptyList(),
    /**
     * Http methods and ant patterns that won't be checked against the db to check if the user exists, mostly used for user creation endpoints
     */
    val unauthenticatedAntPatterns: List<String> = emptyList(),
    /**
     * Requests that won't be checked against the db to check if the user exists, mostly used for user creation endpoints
     */
    val unauthenticatedRequests: List<Request> = emptyList(),
    /**
     * Details regarding firebase as an Sso provider
     */
    val firebase: Firebase?
) {

    sealed class SsoProvider(
        open val enabled: Boolean
    ) {
        data class Firebase(
            override val enabled: Boolean = true,
            val databaseUrl: String,
            val privateKeyFile: String = DEFAULT_FIREBASE_KEY_LOCATION,
            val authorizationHeaderName: String = DEFAULT_FIREBASE_AUTH_HEADER_NAME
        ) : SsoProvider(enabled) {
            companion object {
                private const val DEFAULT_FIREBASE_KEY_LOCATION = "/firebase/private-key.json"
                private const val DEFAULT_FIREBASE_AUTH_HEADER_NAME = "X-Authorization-Firebase"
            }
        }
    }

    data class Request(
        val method: String,
        val path: String,
        val params: List<String>?
    ) : RequestMatcher {
        override fun matches(request: HttpServletRequest): Boolean =
            request.requestURI == path && request.method == method && params?.let { params ->
                params.all { request.queryString.contains(it) }
            } ?: true
    }
}

