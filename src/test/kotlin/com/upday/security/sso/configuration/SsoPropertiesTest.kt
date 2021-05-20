package com.upday.security.sso.configuration

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import javax.servlet.http.HttpServletRequest

internal class SsoPropertiesTest {

    @Test
    fun `should match request`() {
        val request = SsoProperties.Request(
            method = "GET", path = "api/resource", params = listOf("param1", "param2")
        )
        val mockRequest = mockk<HttpServletRequest>()
        every { mockRequest.requestURI } returns request.path
        every { mockRequest.method } returns request.method
        every { mockRequest.queryString } returns "param1=par&param2=par"

        assertTrue(request.matches(mockRequest))
    }

}
