<?php

namespace AnrDaemon\Net\Ldap;

class SearchResponseParser {

    static function parse(array $response): array {
        $result = [];
        $ec = $response["count"];
        for ($i = 0; $i < $ec; $i++) {
            $entry = [
                "dn" => $response[$i]["dn"],
            ];
            $fc = $response[$i]["count"];
            for ($f = 0; $f < $fc; $f++) {
                $field = $response[$i][$f];
                $vc = $response[$i][$field]["count"];
                for ($v = 0; $v < $vc; $v++) {
                    $entry[$field][] = $response[$i][$field][$v];
                }
            }
            $result[] = $entry;
        }

        return $result;
    }
}
