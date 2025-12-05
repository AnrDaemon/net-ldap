<?php

/**
 *
 */

namespace AnrDaemon\Net;

use AnrDaemon\Exceptions\LdapException;

if (defined("LDAP_OPT_X_TLS_CACERTDIR") && \extension_loaded("openssl") && ini_get("openssl.capath")) {
    \ldap_set_option(null, \LDAP_OPT_X_TLS_CACERTDIR, ini_get("openssl.capath"));
}
if (defined("LDAP_OPT_X_TLS_CACERTFILE") && \extension_loaded("openssl") && ini_get("openssl.cafile")) {
    \ldap_set_option(null, \LDAP_OPT_X_TLS_CACERTFILE, ini_get("openssl.cafile"));
}

/**
 * OOP wrapper over standard ldap extension
 */
class Ldap {

    /** Default protocol minimum version
     *
     * Can be overriddedn on object creation.
     *
     * @var int
     */
    const PROTO_MIN_VERSION = 3;


    private $ldapUri = null;


    private $ldap = null;


    public static function escape(string $value, string $ignore, int $flags = 0): string {
        return \ldap_escape($value, $ignore, $flags);
    }


    public static function escapeDn(string $value): string {
        return static::escape($value, "", \LDAP_ESCAPE_DN);
    }


    public static function escapeFilter(string $value): string {
        return static::escape($value, "", \LDAP_ESCAPE_FILTER);
    }

    /** The ldap wrapper itself.
     *
     * Performs an actual call to the library and judges the result.
     *
     * An exception is thrown if results are found inadequate.
     *
     * @param callable $callback The name of ldap_* function to call.
     * @param mixed ...$params Arguments to the call.
     * @return mixed The results of the call.
     */
    protected function perform(callable $callback, &...$params) {
        if ($callback === "ldap_search") {
            $ldap = array_fill(0, sizeof($params[0]), $this->ldap);
        } else {
            $ldap = $this->ldap;
        }
        $success = @$callback($ldap, ...$params);
        if (
            !$success
            || ($callback === "ldap_compare" && $success === -1)
        ) {
            throw $this->ldap ? LdapException::fromInstance($this->ldap) : new LdapException("Failed to set the LDAP_OPT_DEBUG_LEVEL", -1);
        }

        // @TODO Actually use this code, remeber the `ldap_search` array response
        if (is_object($success) && $success instanceof \LDAP\Result || is_resource($success) && get_resource_type($success) === "ldap result") {
            $this->perform("ldap_parse_result", $success, $errcode, $dn, $errmsg, $refs);
        }

        return $success;
    }


    public function setOpt(int $opt, $value): void {
        $this->perform("ldap_set_option", $opt, $value);
    }


    public function getOpt(int $opt) {
        $value = null;
        $this->perform("ldap_get_option", $opt, $value);
        return $value;
    }


    public function startTls(): self {
        if (\strpos($this->ldapUri, "ldaps://") !== 0) {
            $this->perform("ldap_start_tls");
        }

        return $this;
    }


    public function bind(string $dn, string $password): void {
        $this->perform("ldap_bind", $dn, $password);
    }

    /** Performs search in LDAP and returns a list of records
     *
     * It will perform a multithreaded search, if `$base` or `$filter` is an array.
     *
     * If both arguments are arrays, their size must match exactly.
     *
     * @param string|string[] $base
     * @param string|string[] $filter
     * @param string[] $attributes
     * @param int $attributes_only
     * @param int $sizelimit
     * @param int $timelimit
     * @param int $deref
     * @param ?array $controls
     * @return array[]
     */
    public function search($base, $filter, $attributes = [], int $attributes_only = 0, int $sizelimit = -1, int $timelimit = -1, int $deref = \LDAP_DEREF_NEVER, ?array $controls = null): array {
        $count = 1;
        if (is_array($base)) {
            $count = sizeof($base);
        }
        if (is_array($filter)) {
            if (is_array($base) && sizeof($filter) !== $count) {
                throw new LdapException("The \$base and \$filter arguments' count must match for multithreaded query", -1);
            }

            $count = sizeof($filter);
        }
        if (!is_array($base)) {
            $base = array_fill(0, $count, $base);
        }
        if (!is_array($filter)) {
            $filter = array_fill(0, $count, $filter);
        }
        if (version_compare(\PHP_VERSION, "7.3.0", "<")) {
            $result = $this->perform("ldap_search", $base, $filter, $attributes, $attributes_only, $sizelimit, $timelimit, $deref);
        } else {
            $result = $this->perform("ldap_search", $base, $filter, $attributes, $attributes_only, $sizelimit, $timelimit, $deref, $controls);
        }
        return array_map([$this, "perform"], array_fill(0, sizeof($base), "ldap_get_entries"), $result);
    }


    public function __construct(string $ldapUri, ?int $minVersion = self::PROTO_MIN_VERSION, ?int $debugLevel = 0) {
        $this->setOpt(\LDAP_OPT_DEBUG_LEVEL, $debugLevel ?? 0);
        $ldap = \ldap_connect($ldapUri);
        if (empty($ldapUri) || !$ldap) {
            throw new LdapException("Invalid LDAP URI");
        }

        $this->ldapUri = $ldapUri;
        $this->ldap = $ldap;
        $pver = $this->getOpt(\LDAP_OPT_PROTOCOL_VERSION);
        if ($pver < ($minVersion ?? static::PROTO_MIN_VERSION)) {
            $this->setOpt(\LDAP_OPT_PROTOCOL_VERSION, $minVersion ?? static::PROTO_MIN_VERSION);
        }
    }
}
