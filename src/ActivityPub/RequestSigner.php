<?php

namespace AP\ActivityPub;

use AP\Exceptions\APSigningEmptyContentTypeException;
use AP\Exceptions\APSigningEmptyPostBodyException;
use AP\Exceptions\APSigningOpenSSLException;
use AP\Exceptions\APSigningUnsupportedVerbException;

class RequestSigner extends BaseSignature
{

// Returns associative array of headers to return

    /**
     * @param string $privkey
     * @param string $keyid
     * @param int $time
     * @param string $method
     * @param string $url
     * @param string|null $body
     * @param string|null $contenttype
     * @return array
     * @throws APSigningEmptyContentTypeException
     * @throws APSigningEmptyPostBodyException
     * @throws APSigningOpenSSLException
     * @throws APSigningUnsupportedVerbException
     */
    public function signRequest(string $privkey, string $keyid, int $time, string $method, string $url, string $body = null, string $contenttype = null): array
    {
        $headers_out = [
            "Signature" => '',
            "Host" => parse_url($url, PHP_URL_HOST)
        ];

        $sig_params = [
            'algorithm' => 'rsa-sha256',
            'keyId' => $keyid,
            'headers' => []
        ];
        $method = strtolower($method);
        if ('get' == $method) {
            $sig_params['headers'] = ['(request-target)', 'host', 'date'];

        } elseif ('post' == $method) {
            $sig_params['headers'] = ['(request-target)', 'host', 'digest', 'content-type'];
            if (empty($body)) {
                throw new APSigningEmptyPostBodyException(self::ERR_EMPTY_POST_BODY);
            }
            $headers_out['Digest'] = 'SHA-256='.base64_encode(hash('sha256', $body));

            if (empty($contenttype)) {
                throw new APSigningEmptyContentTypeException(self::ERR_EMPTY_CONTENTTYPE);
            }
            $headers_out['Content-Type'] = $contenttype;
        } else {
            // Unsupported HTTP verb
            throw new APSigningUnsupportedVerbException(self::ERR_UNSUPPORTED_VERB);
        }

        if (0 == $time) {
            $time = time();
        }
        // (DATE_RFC7231, or "D, d M Y H:i:s \G\M\T", if you need to support PHP <7.1.5 and <7.0.19)
        $date = gmdate(DATE_RFC7231, $time);
        $headers_out['Date'] = $date;

        // Extract path from $url, as needed for (request-target) meta header
        $query = parse_url($url, PHP_URL_QUERY);
        $path = parse_url($url, PHP_URL_PATH) . ($query ? '?'.$query : '');

        $canon_headers = array_change_key_case($headers_out);
        $canon_headers['(request-target)'] = strtolower($method).' '.$path;

        $canon = $this->canonicalizeHeadersForSig($sig_params['headers'], $canon_headers);

        if (!openssl_sign($canon, $signature, $privkey, OPENSSL_ALGO_SHA256)) {
            throw new APSigningOpenSSLException(self::ERR_OPENSSL_ERROR);
        }

        $sig_params['signature'] = base64_encode($signature);
        $sig_params['headers'] = implode(' ', $sig_params['headers']);
        $parts = [];
        foreach($sig_params as $key => $val) {
            $parts[] = $key.'="'.$val.'"';
        }
        $headers_out['Signature'] = implode(',', $parts);

        return $headers_out;
    }
}