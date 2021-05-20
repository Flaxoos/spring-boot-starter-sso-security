package com.upday.security.sso.user

/**
 * Interface representing the sso user principal
 *
 * @param UID the type of the sso uid (noramlly [String])
 *
 * @author Ido Flasch
 */
interface SsoUser<UID> {
    val uid: UID
}
