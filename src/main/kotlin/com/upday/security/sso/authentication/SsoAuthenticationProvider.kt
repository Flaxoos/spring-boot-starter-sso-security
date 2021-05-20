package com.upday.security.sso.authentication

import com.upday.security.sso.authentication.SsoAuthenticationToken.PreAuthenticationToken
import com.upday.security.sso.excpetions.SsoException
import com.upday.security.sso.user.SsoUser
import com.upday.security.sso.user.SsoUserService
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component

/**
 * Sso authentication provider, responsible for performing user authentication against the DB
 *
 * @property userService the service used to access the DB
 *
 * @author Ido Flasch
 */
@Component
class SsoAuthenticationProvider<UID>(
    private val userService: SsoUserService<UID, out SsoUser<UID>>,
    private val ssoAuthenticationTokenProvider: SsoAuthenticationTokenProvider<UID>,
) : AuthenticationProvider {

    override fun supports(authentication: Class<*>) =
        PreAuthenticationToken::class.java.isAssignableFrom(authentication)

    override fun authenticate(authentication: Authentication): Authentication? {
        if (!supports(authentication::class.java)) return null
        return if ((authentication as PreAuthenticationToken<UID>).verifyAgainstDb) {
            val user = userService.getUserByUid(authentication.principal) ?: throw SsoException.UserNotFoundException()
            ssoAuthenticationTokenProvider.createAuthenticatedUserToken(
                user = user,
                credentials = authentication.credentials
            )
        } else {
            ssoAuthenticationTokenProvider.createNewUserAuthentication(
                authentication.principal as String,
                authentication.credentials
            )
        }
    }


}
