package com.upday.security.sso.authentication

import com.upday.security.sso.user.SsoUser
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

/**
 * Abstract class that represents authentication token generated when the verifying sso token sent by the client
 *
 * @property principal the extracted principal
 * @property credentials the extracted credentials
 * @param authorities any granted authorities
 *
 * @author Ido Flasch
 */
sealed class SsoAuthenticationToken<PRINCIPAL>(
    private val principal: PRINCIPAL,
    private val credentials: Any,
    authorities: Collection<GrantedAuthority>? = null
) : AbstractAuthenticationToken(
    authorities
) {
    override fun getCredentials() = credentials

    override fun getPrincipal() = principal

    /**
     * Token used to indicate the user has not yet been authenticated
     *
     * @param principal sso Uid
     * @param credentials
     */
    class PreAuthenticationToken<UID>(
        principal: UID,
        credentials: Any,
        val verifyAgainstDb: Boolean = true,
        authorities: Collection<GrantedAuthority>? = null
    ) : SsoAuthenticationToken<UID>(
        principal,
        credentials,
        authorities
    ) {
        init {
            isAuthenticated = false
        }
    }

    /**
     * Post authentication token
     *
     * @param PRINCIPAL the [principal] type
     * @constructor
     *
     * @param principal the principal, user or uid
     * @param credentials the authentication credentials
     * @param authorities the authentication authorities
     */
    sealed class PostAuthenticationToken<PRINCIPAL>(
        principal: PRINCIPAL,
        credentials: Any,
        authorities: Collection<GrantedAuthority>? = null
    ) : SsoAuthenticationToken<PRINCIPAL>(
        principal,
        credentials,
        authorities
    ) {
        init {
            isAuthenticated = true
        }

        /**
         * Token used to indicate user has been authenticated, holds the user as the principal
         */
        class AuthenticatedUserToken<UID, USER : SsoUser<UID>>(
            user: USER,
            credentials: Any,
            authorities: Collection<GrantedAuthority>? = null
        ) : PostAuthenticationToken<USER>(
            user,
            credentials,
            authorities
        ) {
            fun getUser(): USER = principal
        }

        /**
         * Token used to authenticate requests for user creation, as uncreated users cannot be verified against the DB
         */
        class NewUserAuthenticationToken(
            idToken: String,
            credentials: Any,
        ) : PostAuthenticationToken<String>(
            idToken,
            credentials
        )
    }

}
