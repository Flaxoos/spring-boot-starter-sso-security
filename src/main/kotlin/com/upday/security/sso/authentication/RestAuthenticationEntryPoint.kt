package com.upday.security.sso.authentication

import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import org.springframework.web.servlet.HandlerExceptionResolver
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Rest authentication entry point, binds the the [exceptionResolver] defined in the project using this library to the authentication process
 *
 * @property exceptionResolver the exception resolver used by the project using this library
 * @constructor Create empty Rest authentication entry point
 *
 * @author Ido Flasch
 */
@Component
class RestAuthenticationEntryPoint(
    @Qualifier("handlerExceptionResolver") private val exceptionResolver: HandlerExceptionResolver
): AuthenticationEntryPoint {
    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        exceptionResolver.resolveException(request, response, null, authException)
    }
}
