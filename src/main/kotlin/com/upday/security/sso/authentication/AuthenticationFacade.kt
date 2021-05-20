package com.upday.security.sso.authentication

import com.upday.security.sso.authentication.SsoAuthenticationToken.PostAuthenticationToken.AuthenticatedUserToken
import com.upday.security.sso.authentication.SsoAuthenticationToken.PostAuthenticationToken.NewUserAuthenticationToken
import com.upday.security.sso.user.SsoUser
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component

/**
 * Authentication facade used to expose the sso user or it's sso uid from the authentication context
 *
 * @param UID the type of the sso uid
 * @param USER the type used to represent the user
 *
 * @author Ido Flasch
 */
@Component
class AuthenticationFacade<UID, USER : SsoUser<UID>> {

    /**
     * Get authenticated user from the security context
     *
     */
    fun getAuthenticatedUser(): USER =
        (getAuthentication() as AuthenticatedUserToken<UID, USER>).getUser()

    /**
     * Get new user uid from the security context
     *
     */
    fun getNewUserUid() =
        (getAuthentication() as NewUserAuthenticationToken).principal

    private fun getAuthentication(): Authentication = SecurityContextHolder.getContext().authentication

}
