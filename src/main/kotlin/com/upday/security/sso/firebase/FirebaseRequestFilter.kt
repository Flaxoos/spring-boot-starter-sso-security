package com.upday.security.sso.firebase

import com.upday.security.sso.configuration.SsoProperties
import com.upday.security.sso.filters.SsoRequestFilter
import org.springframework.stereotype.Component

/**
 * Firebase implementation of [SsoRequestFilter]
 *
 * @param ssoProperties the sso properties
 * @param firebaseAuthenticationTokenProvider the firebase authentication token provider
 *
 * @author Ido Flasch
 */
@Component
class FirebaseRequestFilter(
    ssoProperties: SsoProperties,
    firebaseAuthenticationTokenProvider: FirebaseAuthenticationTokenProvider
) : SsoRequestFilter(
    ssoProperties,
    firebaseAuthenticationTokenProvider,
    ssoProperties.firebase?.authorizationHeaderName
)
