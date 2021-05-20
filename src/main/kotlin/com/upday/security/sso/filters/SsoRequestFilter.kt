package com.upday.security.sso.filters

import com.upday.security.sso.authentication.SsoAuthenticationTokenProvider
import com.upday.security.sso.configuration.SsoProperties
import com.upday.security.sso.excpetions.SsoException.SsoRequestFilterException.MissingHeaderException
import com.upday.security.sso.excpetions.SsoException.SsoRequestFilterException.SsoTokenVerificationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.OncePerRequestFilter
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * abstract request filter for reading id tokens and generating SsoAuthenticationTokens
 *
 * @property ssoProperties the sso properties
 * @property ssoAuthenticationTokenProvider the appropriate authentication token provider for the sso implementation
 * @property authHeaderName the header name used for extracting the id token
 *
 * @author Ido Flasch
 */
abstract class SsoRequestFilter(
    private val ssoProperties: SsoProperties,
    private val ssoAuthenticationTokenProvider: SsoAuthenticationTokenProvider<*>,
    private val authHeaderName: String
) : OncePerRequestFilter() {

    /**
     * Looks for the [authHeaderName] in the request headers and passes it's value to the [ssoAuthenticationTokenProvider]
     * to generate an authentication token
     *
     * @param request the request
     * @param response the response
     * @param filterChain the filter chain
     */
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val xAuth = request.getHeader(authHeaderName) ?: throw MissingHeaderException(
            authHeaderName
        )
        try {
            SecurityContextHolder.getContext().authentication =
                ssoAuthenticationTokenProvider.createPreAuthenticationToken(xAuth, shouldVerifyAgainstDb(request))
        } catch (e: Exception) {
            throw SsoTokenVerificationException(e)
        }
        filterChain.doFilter(request, response)
    }

    override fun shouldNotFilter(request: HttpServletRequest): Boolean =
        ssoProperties.disableForAntPatterns.map { it.removeSuffix("/**") }
            .map { request.requestURI.contains(it) }
            .union(ssoProperties.disableForRequests.map {
                it.matches(request)
            }).reduce { a, b -> a || b }


    private fun shouldVerifyAgainstDb(request: HttpServletRequest): Boolean =
        ssoProperties.unauthenticatedRequests
            .map { !it.matches(request) }.reduce { a, b -> a && b }

}

