<?php

namespace AP\ActivityPub;

use AP\Exceptions\APDigestMismatchException;
use AP\Exceptions\APExpirationExpiredException;
use AP\Exceptions\APExpirationTooNewException;
use AP\Exceptions\APMalformedDigestException;
use AP\Exceptions\APMissingHeaderException;
use AP\Exceptions\APMissingSignatureDateException;
use AP\Exceptions\APNoDigestException;
use AP\Exceptions\APNoKeyException;
use AP\Exceptions\APNoSignatureAlgorithmException;
use AP\Exceptions\APNoSignatureHeadersException;
use AP\Exceptions\APNoSignatureValueException;
use AP\Exceptions\APSignatureException;
use AP\Exceptions\APSignatureMismatchException;
use AP\Exceptions\APSigningEmptyContentTypeException;
use AP\Exceptions\APSigningEmptyPostBodyException;
use AP\Exceptions\APSigningOpenSSLException;
use AP\Exceptions\APSigningUnsupportedVerbException;
use AP\Exceptions\APUnsignedRequestException;
use AP\Exceptions\APUnsupportedAlgorithmException;
use AP\Exceptions\APUnsupportedHashException;
use AP\Exceptions\APUnsupportedMethodException;
use AP\Exceptions\APWeakCoverageException;

class SignatureValidator extends BaseSignature
{


    /**
     * @param string $signature_header_value
     * @return array
     * @throws APNoKeyException
     * @throws APSignatureException
     */
    public function parseSignatureParams(string $signature_header_value): array
    {
        preg_match_all('/(?<key>[a-zA-Z]+)="(?<val>[^"]+)"(,\s*|$)/', $signature_header_value, $matches);

        // Combine matches of keys and values into an associatiove array of key => val
        $params = array_combine($matches['key'], $matches['val']);

        // Check for required parameters
        if (!array_key_exists('keyId', $params)) {
            throw new APNoKeyException(self::ERR_NO_KEYID);
        } elseif (!array_key_exists('signature', $params)) {
            throw new APNoSignatureValueException(self::ERR_NO_SIG_VALUE);
        } elseif (!array_key_exists('algorithm', $params)) {
            throw new APNoSignatureAlgorithmException(self::ERR_NO_SIG_ALGO);
        } elseif (!array_key_exists('headers', $params)) {
            throw new APNoSignatureHeadersException(self::ERR_NO_SIG_HEADERS);
        }
        $params['headers'] = explode(' ', $params['headers']);
        return $params;
    }

    /**
     * @param array $sig_params
     * @param string $method
     * @return bool
     * @throws APSignatureException
     */
    public function safeSignatureCoverage(array $sig_params, string $method): bool
    {
        $method = strtolower($method);
        if ('get' == $method) {
            $missing_required = array_diff(
                ['(request-target)', 'host', 'date', 'digest'], // @XXX Can mandate content-type too
                $sig_params['headers']
            );
        } elseif ('post' == $method) {
            $missing_required = array_diff(
                ['(request-target)', 'host', 'date'],
                $sig_params['headers']
            );
        } else {
            throw new APUnsupportedMethodException(self::ERR_UNSUPPORTED_METHOD);
        }

        if (count($missing_required)) {
            if (in_array('date', $missing_required)
                and in_array('(created)', $sig_params['headers'])
                and count($missing_required) == 1) {
                // Accept (created) as substitute for 'date', if it's the only one 'missing'
                return true;
            }
            throw new APWeakCoverageException(self::ERR_WEAK_COVERAGE);
        }
        return true;
    }


    /**
     * @param string $digest_header
     * @param string $body
     * @return bool
     * @throws APDigestMismatchException
     * @throws APMalformedDigestException
     * @throws APUnsupportedHashException
     */
    public function verifyDigest(string $digest_header, string $body): bool
    {
        $digest_parts = explode('=', $digest_header, 2);
        if (count($digest_parts) != 2) {
            throw new APMalformedDigestException(self::ERR_MALFORMED_DIGEST);
        }
        $digest_algo = strtolower( str_replace('-','', $digest_parts[0]));
        $digest_hash = $digest_parts[1];

        if (!in_array($digest_algo, ['sha224', 'sha256', 'sha384', 'sha512'])) {
            throw new APUnsupportedHashException(self::ERR_UNSUPPORTED_HASH);
        }
        $computed = base64_encode( hash($digest_algo, $body, true) );

        if  ($computed === $digest_hash) {
            return true;
        }
        throw new APDigestMismatchException(self::ERR_DIGEST_MISMATCH);
    }

    /**
     * @param int $time
     * @param array $headers
     * @param array $sig_params
     * @return bool
     * @throws APSignatureException
     */
    public function verifyExpiry(int $time, array $headers, array $sig_params): bool
    {
        $lifetime_limit = 43200; // 12 hours, (60 * 60 * 20 seconds)

        if (array_key_exists('date', $headers)) {
            // Request has Date header
            $sig_date = date_create_from_format(DATE_RFC7231, $headers['date']);
            $sig_unix = intval($sig_date->format('U'));

            if ($sig_unix > $time) {
                throw new APExpirationTooNewException(self::ERR_TOO_NEW);
            }
            if ($time > ($sig_unix + $lifetime_limit)) {
                throw new APExpirationExpiredException(self::ERR_EXPIRED);
            }
            return true;
        } elseif (array_key_exists('created', $sig_params)) {
            // Signature has 'created' param
            $created = intval($sig_params['created']);

            if (array_key_exists('expires', $sig_params)) {
                $expires = intval($sig_params['expires']);
                if ($time > $expires) {
                    throw new APExpirationExpiredException(self::ERR_EXPIRED);
                }
            }
            if ($created > $time) {
                throw new APExpirationTooNewException(self::ERR_TOO_NEW);
            }
            if ($time > ($created + $lifetime_limit)) {
                throw new APExpirationExpiredException(self::ERR_EXPIRED);
            }
            return true;
        }
        // Request lacks Date header and 'created' signature parameter
        throw new APMissingSignatureDateException(self::ERR_MISSING_SIG_DATE);
    }

    /**
     * @param array $sig_params
     * @param string $pubkey
     * @param string $method
     * @param string $path
     * @param array $headers
     * @param string $body
     * @return bool
     * @throws APMissingHeaderException
     * @throws APNoDigestException
     * @throws APSignatureMismatchException
     * @throws APUnsignedRequestException
     */
    public function verifySignature(array $sig_params, string $pubkey, string $method, string $path, array $headers, string $body = ''): bool
    {
        /* $headers is assumed to be an associative array, e.g. ["Signature" => "value", "Digest" => "value", (etc..) ], not a list of strings) */

        // Lowercase the method verb, as part of canonicalization
        $method = strtolower($method);

        // Lowercase the header names, as part of canonicalization
        $headers = array_change_key_case($headers);

        if (!array_key_exists('signature', $headers)) {
            throw new APUnsignedRequestException(self::ERR_UNSIGNED);
        }

        if ('post' == $method) {
            if (!array_key_exists('digest', $headers)) {
                throw new APNoDigestException(self::ERR_NO_DIGEST);
            }
            /*
            $digest_verify = verify_digest($headers['digest'], $body);
            if ($digest_verify !== true) {
                return $digest_verify;
            }
             */
        }
        /* (request-target) is just a generated meta header to represent the
         * request verb and path (since those aren't part of the header list) for signing */
        $headers['(request-target)'] = $method.' '.$path;

        // From the HTTP Signatures spec, although it's not really used anywhere in fedi
        if (array_key_exists('created', $sig_params)) {
            $headers['(created)'] = $sig_params['created'];
        }
        if (array_key_exists('expires', $sig_params)) {
            $headers['(expires)'] = $sig_params['expires'];
        }

        $missing_headers = array_diff($sig_params['headers'], array_keys($headers));
        if (count($missing_headers)) {
            // Header referenced in signature doesn't exist (or wasn't passed)
            throw new APMissingHeaderException(self::ERR_MISSING_HEADER);
        }

        $canon = $this->canonicalizeHeadersForSig($sig_params['headers'], $headers);

        $valid = openssl_verify($canon, base64_decode($sig_params['signature']), $pubkey, OPENSSL_ALGO_SHA256);
        if ($valid === 1) {
            return true;
        }
        throw new APSignatureMismatchException(self::ERR_SIG_MISMATCH);
    }


    /***
     * Main business-logic functions for verifying/signing requests follow
     ***/
    /**
     * @param $request
     * @param $pubkey
     * @param int $time
     * @return bool
     * @throws APNoKeyException
     * @throws APSignatureException
     */
    public function verifyRequestSignature($request, $pubkey, int $time = 0): bool
    {
        // Lowercase the header names, for more canonicalized lookup
        $headers = array_change_key_case($request['headers']);

        if (!array_key_exists('signature', $headers)) {
            throw new APUnsignedRequestException(self::ERR_UNSIGNED);
        }

        $sig_params = $this->parseSignatureParams($headers['signature']);

        // No ECC-based sig algos standardized in the HTTP Signature spec;
        // only RSA and HMAC.
        if ('rsa-sha256' !== $sig_params['algorithm']) {
            throw new APUnsupportedAlgorithmException(self::ERR_UNSUPPORTED_ALGO);
        }

        // Test (created) and (expired)?
        $sig_safety = $this->safeSignatureCoverage($sig_params, $request['method']);


        if (0 == $time) {
            $time = time();
        }

        $this->verifyExpiry($time, $headers, $sig_params);

        if (!array_key_exists('digest', $headers)) {
            throw new APNoDigestException(self::ERR_NO_DIGEST);
        }

        if ('post' === strtolower($request['method'])) {
            $this->verifyDigest($headers['digest'], $request['body']);
        }

        $this->verifySignature($sig_params, $pubkey, $request['method'], $request['path'], $headers);

        return true;
    }


}