package com.upday.security.sso.user

/**
 * Interface representing the component used to retrieve the user using the sso uid, should be implemented by the project using this library
 *
 * @param UID the type of the uid (normally [String])
 * @param USER the type of the User, should implement [SsoUser]
 *
 * @author Ido Flasch
 */
interface SsoUserService<UID, USER : SsoUser<UID>> {
    fun getUserByUid(uid: UID): USER?
}
