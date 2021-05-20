package com.upday.security.sso.configuration

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.*
import org.springframework.core.type.AnnotatedTypeMetadata

/**
 * Auto configuration to fo
 *
 * @author Ido Flasch
 */
@EnableConfigurationProperties(SsoProperties::class)
@ComponentScan(basePackages = ["com.upday.security.sso"])
class SsoAutoConfiguration
