package com.upday.security.sso.filters

import com.upday.security.sso.configuration.SsoProperties
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.stereotype.Component

/**
 * Sso filter configurer used to configure the http security by adding the given [ssoRequestFilter] to the filter chain in the correct place
 *
 * @property ssoProperties the library properties
 * @property ssoRequestFilter the sso request filter
 * @constructor Create empty Sso filter configurer
 *
 * @author Ido Flasch
 */
@Component
@Order(HIGHEST_PRECEDENCE)
class SsoFilterConfigurer(
    private val ssoProperties: SsoProperties,
    private val ssoRequestFilter: SsoRequestFilter,
    private val ssoRequestFilterExceptionHandler: SsoRequestFilterExceptionHandler
) {

    /**
     * adds the given [ssoRequestFilter] in the correct position in the chain
     *
     * @param http
     */
    fun setupFilters(http: HttpSecurity) {
        if (ssoProperties.firebase?.enabled == true) http.addSsoFilter(ssoRequestFilter)
    }

    private fun HttpSecurity.addSsoFilter(filter: SsoRequestFilter) {
        addFilterBefore(filter, BasicAuthenticationFilter::class.java)
            .addFilterBefore(ssoRequestFilterExceptionHandler, ChannelProcessingFilter::class.java)
    }
}
