package com.upday.security.sso.authentication

import com.upday.security.sso.authentication.SsoAuthenticationToken.PostAuthenticationToken.AuthenticatedUserToken
import com.upday.security.sso.authentication.SsoAuthenticationToken.PostAuthenticationToken.NewUserAuthenticationToken
import com.upday.security.sso.authentication.SsoAuthenticationToken.PreAuthenticationToken
import com.upday.security.sso.user.SsoUser

/**
 * Interface for creating sso authentication tokens, should be implemented for the appropriate sso implementation
 *
 * @param UID the type of the uid used by the application
 *
 * @author Ido Flasch
 */
interface SsoAuthenticationTokenProvider<UID> {

    /**
     * Create pre authentication token, needs to be implemented to verify id token using applicable sso provider
     *
     * @param idToken
     * @param verifyAgainstDb
     * @return the pre authentication token
     */
    fun createPreAuthenticationToken(idToken: String, verifyAgainstDb: Boolean = true): PreAuthenticationToken<UID>

    /**
     * Create authenticated user token token, for user after authentication success
     *ז
     * @param user
     * @param credentials
     * @return the authenticated user token
     */
    fun <USER : SsoUser<UID>> createAuthenticatedUserToken(
        user: USER,
        credentials: Any
    ): AuthenticatedUserToken<UID, USER> =
        AuthenticatedUserToken(
            user,
            credentials
        )

    /**
     * Create new user authentication token, for use for yet uncreated user authentication
     *
     * @param idToken
     * @param credentials
     * @return the new user token
     */
    fun createNewUserAuthentication(idToken: String, credentials: Any): NewUserAuthenticationToken =
        NewUserAuthenticationToken(idToken, credentials)


}
