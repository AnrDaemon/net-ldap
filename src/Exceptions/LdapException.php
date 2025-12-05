<?php

/** ldap errors wrapper
 */

namespace AnrDaemon\Exceptions;

use LDAP\Connection;

/** The ldap errors wrapper class
 */
class LdapException
extends \Exception {

    /** Creates an exception from LDAP instance data
     *
     * @param \LDAP\Connection|resource $ldap
     * @param ?\Exception $previous
     * @return void
     */
    public static function fromInstance($ldap, \Throwable $previous = null) {
        if (!(\is_object($ldap) && $ldap instanceof Connection || \is_resource($ldap) && \get_resource_type($ldap) === 'ldap link')) {
            throw new \Exception("Requires a ldap instance to proceed", -1, $previous);
        }

        \ldap_get_option($ldap, \LDAP_OPT_ERROR_NUMBER, $error);
        $message = \ldap_err2str($error);
        \ldap_get_option($ldap, \LDAP_OPT_ERROR_STRING, $text);
        return new static("$message: $text", $error, $previous);
    }
}
