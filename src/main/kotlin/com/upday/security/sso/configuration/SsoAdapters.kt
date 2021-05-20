package com.upday.security.sso.configuration

import com.upday.security.sso.authentication.SsoAuthenticationProvider
import com.upday.security.sso.filters.SsoFilterConfigurer
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered.HIGHEST_PRECEDENCE
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer
import org.springframework.security.config.http.SessionCreationPolicy

/**
 * Sso adapters - used to configure spring security to enable sso
 *
 * @constructor Create empty Sso adapters
 *
 * @author Ido Flasch
 */
class SsoAdapters {

    @Configuration
    @Order(HIGHEST_PRECEDENCE)
    class SsoAuthenticationAdapter(
        private val ssoAuthenticationProvider: SsoAuthenticationProvider<*>
    ) : GlobalAuthenticationConfigurerAdapter() {

        override fun init(auth: AuthenticationManagerBuilder) {
            auth.authenticationProvider(ssoAuthenticationProvider)
        }
    }

    @Configuration
    @Order(HIGHEST_PRECEDENCE + 1)
    class SsoConfigurerAdapter(
        private val ssoFilterConfigurer: SsoFilterConfigurer,
        private val ssoProperties: SsoProperties
    ) : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http.authorizeRequests()
                .adaptDefinedRequests()
                .and()
                .cors()
                .and().csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .headers()
                .cacheControl()
            ssoFilterConfigurer.setupFilters(http)
        }

        private fun ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry.adaptDefinedRequests() =
            requestMatchers(*ssoProperties.disableForRequests.toTypedArray()).permitAll()
                .antMatchers(*ssoProperties.disableForAntPatterns.toTypedArray()).permitAll()
                .requestMatchers(*ssoProperties.authenticatedRequests.toTypedArray()).authenticated()
                .antMatchers(*ssoProperties.authenticatedAntPatterns.toTypedArray()).authenticated()

    }
}
