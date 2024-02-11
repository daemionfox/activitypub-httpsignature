<?php

namespace AP\ActivityPub;

class BaseSignature
{

    const ERR_UNSIGNED = "Request lacks Signature header";
    const ERR_INACCESSIBLE_KEY = "Unable to retrieve key located at keyId designated in Signature header";
    const ERR_NO_DIGEST = "Request lacks a Digest header (POST)";
    const ERR_MALFORMED_DIGEST = "Digest header is in a malformed or unsupported format";
    const ERR_MALFORMED_SIG = "Signature header is in a malformed or unsupported format";
    const ERR_NO_KEYID = "Signature header lacks a 'keyId' parameter";
    const ERR_NO_SIG_VALUE = "Signature header lacks a 'signature' parameter";
    const ERR_NO_SIG_ALGO = "Signature header lacks an 'algorithm' paramter";
    const ERR_NO_SIG_HEADERS = "Signature header lacks a 'headers' parameter";
    const ERR_MISSING_SIG_DATE = "Request lacks a Date header";
    const ERR_EXPIRED = "HTTP Signature expired";
    const ERR_TOO_NEW = "HTTP Signature too new (bad system time?)";
    const ERR_UNSUPPORTED_HASH = "Unsupported Digest hash algorithm";
    const ERR_UNSUPPORTED_ALGO = "Unsupported signature algorithm";
    const ERR_UNSUPPORTED_METHOD = "Unsupported HTTP verb for HTTP Signature";
    const ERR_MISSING_HEADER = "Missing header included in signature";
    const ERR_WEAK_COVERAGE = "Signature header coverage too weak";
    const ERR_DIGEST_MISMATCH = "Digest header hash differs from calculated hash of request body";
    const ERR_SIG_MISMATCH = "Signature does not match";
    const ERR_EMPTY_POST_BODY = "Cannot generate digest for empty POST body";
    const ERR_EMPTY_CONTENTTYPE = "Cannot sign POST request without a Content-Type specified";
    const ERR_UNSUPPORTED_VERB = "Cannot sign HTTP request with unsupported HTTP verb";
    const ERR_OPENSSL_ERROR = "Error with performing signature (bad private key format, or wrong key type?)";



    /**
     * @param $header_list
     * @param $headers
     * @return string
     */
    public function canonicalizeHeadersForSig($header_list, $headers): string
    {
        $canon = '';
        $first = true;
        foreach($header_list as $hdr) {
            // Add newline between headers (but not before the first one)
            $canon .= ($first ? '' : "\n") . $hdr.': '.$headers[$hdr];
            $first = false;
        }
        return $canon;
    }

}