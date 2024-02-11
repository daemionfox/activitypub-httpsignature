<?php
define('SIG_UNSIGNED', -1);
define('SIG_INACCESSIBLE_KEY', -2);
define('SIG_NO_DIGEST', -3);
define('SIG_MALFORMED_DIGEST', -4);
define('SIG_MALFORMED_SIG', -5);
define('SIG_NO_KEYID', -6);
define('SIG_NO_SIG_VALUE', -7);
define('SIG_NO_SIG_ALGO', -8);
define('SIG_NO_SIG_HEADERS', -9);
define('SIG_MISSING_SIG_DATE', -10);
define('SIG_EXPIRED', -11);
define('SIG_TOO_NEW', -12);
define('SIG_UNSUPPORTED_HASH', -13);
define('SIG_UNSUPPORTED_ALGO', -14);
define('SIG_UNSUPPORTED_METHOD', -15);
define('SIG_MISSING_HEADER', -16);
define('SIG_WEAK_COVERAGE', -17);
define('SIG_DIGEST_MISMATCH', -18);
define('SIG_SIG_MISMATCH', -19);

define('SIGN_EMPTY_POST_BODY', -32);
define('SIGN_EMPTY_CONTENTTYPE', -33);
define('SIGN_UNSUPPORTED_VERB', -34);
define('SIGN_OPENSSL_ERROR', -35);

function sig_errormsg(int $error) {
    switch($error) {
        case SIG_UNSIGNED:
            return "Request lacks Signature header";
        case SIG_INACCESSIBLE_KEY:
            return "Unable to retrieve key located at keyId designated in Signature header";
        case SIG_NO_DIGEST:
            return "Request lacks a Digest header (POST)";
        case SIG_MALFORMED_DIGEST:
            return "Digest header is in a malformed or unsupported format";
        case SIG_MALFORMED_SIG:
            return "Signature header is in a malformed or unsupported format";
        case SIG_NO_KEYID:
            return "Signature header lacks a 'keyId' parameter";
        case SIG_NO_SIG_VALUE:
            return "Signature header lacks a 'signature' parameter";
        case SIG_NO_SIG_ALGO:
            return "Signature header lacks an 'algorithm' paramter";
        case SIG_NO_SIG_HEADERS:
            return "Signature header lacks a 'headers' parameter";
        case SIG_MISSING_SIG_DATE:
            return "Request lacks a Date header";
        case SIG_EXPIRED:
            return "HTTP Signature expired";
        case SIG_TOO_NEW:
            return "HTTP Signature too new (bad system time?)";
        case SIG_UNSUPPORTED_HASH:
            return "Unsupported Digest hash algorithm";
        case SIG_UNSUPPORTED_ALGO:
            return "Unsupported signature algorithm";
        case SIG_UNSUPPORTED_METHOD:
            return "Unsupported HTTP verb for HTTP Signature";
        case SIG_MISSING_HEADER:
            return "Missing header included in signature";
        case SIG_WEAK_COVERAGE:
            return "Signature header coverage too weak";
        case SIG_DIGEST_MISMATCH:
            return "Digest header hash differs from calculated hash of request body";
        case SIG_SIG_MISMATCH:
            return "Signature does not match";
        case SIGN_EMPTY_POST_BODY:
            return "Cannot generate digest for empty POST body";
        case SIGN_EMPTY_CONTENTTYPE:
            return "Cannot sign POST request without a Content-Type specified";
        case SIGN_UNSUPPORTED_VERB:
            return "Cannot sign HTTP request with unsupported HTTP verb";
        case SIGN_OPENSSL_ERROR:
            return "Error with performing signature (bad private key format, or wrong key type?)";
    }
}

function parse_signature_params(string $signature_header_value) {
    // Regex decodes: key="value",key="value",key="value"
    preg_match_all('/(?<key>[a-zA-Z]+)="(?<val>[^"]+)"(,\s*|$)/', $signature_header_value, $matches);

    // Combine matches of keys and values into an associatiove array of key => val
    $params = array_combine($matches['key'], $matches['val']);

    // Check for required parameters
    if (!array_key_exists('keyId', $params)) {
        return SIG_NO_KEYID;
    } elseif (!array_key_exists('signature', $params)) {
        return SIG_NO_SIG_VALUE;
    } elseif (!array_key_exists('algorithm', $params)) {
        return SIG_NO_SIG_ALGO;
    } elseif (!array_key_exists('headers', $params)) {
        return SIG_NO_SIG_HEADERS;
    }
    $params['headers'] = explode(' ', $params['headers']);
    return $params;
}

function safe_signature_coverage(array $sig_params, string $method) {
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
        return SIG_UNSUPPORTED_METHOD;
    }

    if (count($missing_required)) {
        if (in_array('date', $missing_required)
            and in_array('(created)', $sig_params['headers'])
            and count($missing_required) == 1) {
            // Accept (created) as substitute for 'date', if it's the only one 'missing'
            return true;
        }
        return SIG_WEAK_COVERAGE;
    } else {
        return true;
    }
}

function verify_digest(string $digest_header, string $body) {
    $digest_parts = explode('=', $digest_header, 2);
    if (count($digest_parts) != 2) {
        return SIG_MALFORMED_DIGEST;
    }
    $digest_algo = strtolower( str_replace('-','', $digest_parts[0]));
    $digest_hash = $digest_parts[1];

    if (!in_array($digest_algo, ['sha224', 'sha256', 'sha384', 'sha512'])) {
        return SIG_UNSUPPORTED_HASH;
    }
    $computed = base64_encode( hash($digest_algo, $body, true) );

    if  ($computed === $digest_hash) {
        return true;
    } else {
        return SIG_DIGEST_MISMATCH;
    }
}

function verify_expiry(int $time, array $headers, array $sig_params) {
    $lifetime_limit = 43200; // 12 hours, (60 * 60 * 20 seconds)

    if (array_key_exists('date', $headers)) {
        // Request has Date header
        $sig_date = date_create_from_format(DATE_RFC7231, $headers['date']);
        $sig_unix = intval($sig_date->format('U'));

        if ($sig_unix > $time) {
            return SIG_TOO_NEW;
        }
        if ($time > ($sig_unix + $lifetime_limit)) {
            return SIG_EXPIRED;
        }
        return true;
    } elseif (array_key_exists('created', $sig_params)) {
        // Signature has 'created' param
        $created = intval($sig_params['created']);

        if (array_key_exists('expires', $sig_params)) {
            $expires = intval($sig_params['expires']);
            if ($time > $expires) {
                return SIG_EXPIRED;
            }
        }
        if ($created > $time) {
            return SIG_TOO_NEW;
        }
        if ($time > ($created + $lifetime_limit)) {
            return SIG_EXPIRED;
        }
        return true;
    } else {
        // Request lacks Date header and 'created' signature parameter
        return SIG_MISSING_SIG_DATE;
    }
}

function verify_signature(array $sig_params, string $pubkey, string $method, string $path, array $headers, string $body = '') {
    /* $headers is assumed to be an associative array, e.g. ["Signature" => "value", "Digest" => "value", (etc..) ], not a list of strings) */

    // Lowercase the method verb, as part of canonicalization
    $method = strtolower($method);

    // Lowercase the header names, as part of canonicalization
    $headers = array_change_key_case($headers);

    if (!array_key_exists('signature', $headers)) {
        return SIG_UNSIGNED;
    }

    if ('post' == $method) {
        if (!array_key_exists('digest', $headers)) {
            return SIG_NO_DIGEST;
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
        return SIG_MISSING_HEADER;
    }

    $canon = canonicalize_headers_for_sig($sig_params['headers'], $headers);

    $valid = openssl_verify($canon, base64_decode($sig_params['signature']), $pubkey, OPENSSL_ALGO_SHA256);
    if ($valid) {
        return true;
    } else {
        return SIG_SIG_MISMATCH;
    }
}

function canonicalize_headers_for_sig($header_list, $headers) {
    $canon = '';
    $first = true;
    foreach($header_list as $hdr) {
        // Add newline between headers (but not before the first one)
        $canon .= ($first ? '' : "\n") . $hdr.': '.$headers[$hdr];
        $first = false;
    }
    return $canon;
}

/***
 * Main business-logic functions for verifying/signing requests follow
 ***/
function verify_request_signature($request, $pubkey, int $time = 0, bool $return_errcode = false) {
    // Lowercase the header names, for more canonicalized lookup
    $headers = array_change_key_case($request['headers']);

    if (!array_key_exists('signature', $headers)) {
        // Request lacks a Signature header
        return ($return_errcode ? SIG_UNSIGNED : false);
    }

    $sig_params = parse_signature_params($headers['signature']);
    if (!is_array($sig_params)) {
        // Return error code, if enabled; else return false (safer)
        return ($return_errcode ? $sig_params : false);
    }

    // No ECC-based sig algos standardized in the HTTP Signature spec;
    // only RSA and HMAC.
    if ('rsa-sha256' !== $sig_params['algorithm']) {
        return ($return_errcode ? SIG_UNSUPPORTED_ALGO : false);
    }

    // Test (created) and (expired)?

    $sig_safety = safe_signature_coverage($sig_params, $request['method']);
    if (true !== $sig_safety) {
        return ($return_errcode ? $sig_safety : false);
    }

    if (0 == $time) {
        $time = time();
    }

    $sig_current = verify_expiry($time, $headers, $sig_params);
    if (true !== $sig_current) {
        return ($return_errcode ? $sig_current : false);
    }

    if (!array_key_exists('digest', $headers)) {
        // Request lacks a Digest header
        return ($return_errcode ? SIG_NO_DIGEST : false);
    }

    if ('post' === strtolower($request['method'])) {
        $digest_matches = verify_digest($headers['digest'], $request['body']);
        if (true !== $digest_matches) {
            return ($return_errcode ? $digest_matches : false);
        }
    }

    $valid_sig = verify_signature($sig_params, $pubkey, $request['method'], $request['path'], $headers);
    if (true !== $valid_sig) {
        return ($return_errcode ? $valid_sig : false);
    }
    return true;
}

// Returns associative array of headers to return
function sign_request(string $privkey, string $keyid, int $time, string $method, string $url, string $body = null, string $contenttype = null) {
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
            return SIGN_EMPTY_POST_BODY;
        }
        $headers_out['Digest'] = 'SHA-256='.base64_encode(hash('sha256', $body));

        if (empty($contenttype)) {
            return SIGN_EMPTY_CONTENTTYPE;
        }
        $headers_out['Content-Type'] = $contenttype;
    } else {
        // Unsupported HTTP verb
        return SIGN_UNSUPPORTED_VERB;
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

    $canon = canonicalize_headers_for_sig($sig_params['headers'], $canon_headers);

    if (!openssl_sign($canon, $signature, $privkey, OPENSSL_ALGO_SHA256)) {
        return SIGN_OPENSSL_ERROR;
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

/* * * * * * * * * * * * * TEAR ALONG THE DOTTED LINE * * * * * * * * * * * * */
// Sample code and basic tests follow

ini_set('display_errors', 1);

$sample_request = <<<'HEREDOC'
{
	"method": "POST",
	"path": "/inbox",
	"headers": {
		"content-type": "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
		"host": "mastodon.example",
		"date": "Sun, 11 Feb 2024 10:41:33 GMT",
		"digest": "SHA-256=sg6O7VE7pAo1a0yE6wdnXQGf13XROKnuUdvHlT6W7Bg=",
		"signature": "keyId=\"https://merp.example/users/test#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest content-type\",signature=\"Ib4xcWO1UqFBDzPhIHDJMjO8CxVgg27MygsyAW64EL+owBjjTWVou/3B6sUWAFRwX+wV+6ZGEycLyxaH8zKoueulr5ZSv8q+inGleErgwfCcPT3o4tGgaf4dd1GIXcxxw6c0JeRJSJZ9Ie9zi+41Gc7naz9dCA2eXM4XyLx0Ag61x54CFOwgU1P1koyoIOK+mIlsxuf1oizWRnGOXx3voSPL1PrmfXjLmC+wHrg00tuFrLmKEaJaCtjUZCP8Ocq4P9dfJlPkxac844D8fThVuucpY9HUhUz5kHjolDvF80N+m/iW0vdPlC45Yo50XQa6uaQ8ftKfHcEz7N1/A1Sr2g==\""
	},
	"body": "{\"type\":\"Create\",\"object\":{\"type\":\"Note\",\"content\":\"A quick post.\",\"actor\":\"https://merp.example/users/test\",\"attributedTo\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"sensitive\":false,\"summary\":\"\",\"id\":\"https://merp.example/users/test/posts/2402/11/104046\"},\"actor\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"@context\":[\"https://www.w3.org/ns/activitystreams\"],\"id\":\"https://merp.example/users/test/posts/2402/11#Create-BlyKQu\"}"
}
HEREDOC;
$request = json_decode($sample_request, true);
if (false == $request) {
    die('Failed to parse sample request'. json_last_error_msg());
}

$sample_actor = <<<'HEREDOC'
{
  "@context": ["https://www.w3.org/ns/activitystreams"],
  "id": "https://merp.example/users/test",
  "type": "Person",
  "inbox": "https://merp.example/users/test/inbox",
  "outbox": "https://merp.example/users/test/outbox",
  "preferredUsername": "test",
  "publicKey": {
    "id": "https://merp.example/users/test#main-key",
    "owner": "https://merp.example/users/test",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2P8QViTivQI2WXp43RMb\nLtUH4HXSpBb5GP5iMjHddeelWXlMthp/0t3ofU71ZSCMlyAZ2Z383BOPBLyqtWMk\nm7qdonQZCjC6dfUOYuQT3RnW8USruVai2SWKoQbnBkQL9B4zhqHO0HLQDAMWpcwL\nxSlIxV84mbmYw8+5Qwhgt+KZtAfxx2xgLax0PUlPI4dcaI5uOFY7TqmXkr4KQl+Q\nWKpHwsFdhKbm0hZU9Cyk4O5cB9aqOyH583FtJnS4I9kxxlw9kOL9Un8ClX3kc5dQ\n5MzS2YP3PUhmVJolL1zo0gr/SptbsaFrYyw1qdtfYX0U5EmBf/gegKdRVyoWaA1Q\nswIDAQAB\n-----END PUBLIC KEY-----\n"
  }
}
HEREDOC;
$actor = json_decode($sample_actor, true);
if (false == $actor) {
    die('Failed to parse sample actor: '. json_last_error_msg());
}

if (!function_exists('openssl_verify')) {
    die('Missing PHP OpenSSL extension');
}

// Don't do this, this is just for testing purposes (manually setting 'current time' to a specific date, for validation)
$gmdate = date_create_from_format(DATE_RFC7231, 'Sun, 11 Feb 2024 10:42:39 GMT');
$time = intval($gmdate->format('U'));

// Be mindful that actor[publicKey] might not directly contain an public key definition, but actually a list of public key definitions
$actor_keyid = $actor['publicKey']['id'];
$actor_pubkey = $actor['publicKey']['publicKeyPem'];
$actor_privkey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDY/xBWJOK9AjZZ\nenjdExsu1QfgddKkFvkY/mIyMd1156VZeUy2Gn/S3eh9TvVlIIyXIBnZnfzcE48E\nvKq1YySbup2idBkKMLp19Q5i5BPdGdbxRKu5VqLZJYqhBucGRAv0HjOGoc7QctAM\nAxalzAvFKUjFXziZuZjDz7lDCGC34pm0B/HHbGAtrHQ9SU8jh1xojm44VjtOqZeS\nvgpCX5BYqkfCwV2EpubSFlT0LKTg7lwH1qo7IfnzcW0mdLgj2THGXD2Q4v1SfwKV\nfeRzl1DkzNLZg/c9SGZUmiUvXOjSCv9Km1uxoWtjLDWp219hfRTkSYF/+B6Ap1FX\nKhZoDVCzAgMBAAECggEAInT+JxpcVsm5z6OUUFFEXmoS13WzfmhCIyc3IzlVLUUc\ntdnTxebsp+iiOPkHcTN7SlQdRrfA+0FafdS9AWiThkGv3lKz1zETABVrChD629Uf\n6IKQXNyA/MeVUn9CGCCeCqRGZ6Pcr1pL5wcRMD/3w9W2adZLqpK/dfh6NpwR9PY0\n+8BsMdOnl1PNVqP8+IsbqUW4AyDP1fuloToU4DXEVTAyBVzXSLKfUyIgFNJIKjum\nsyen2iGJ0o6RmDAHZ56pMhAWmZ8doVYzgfv3t4B0q96XddSpRfCDIUTjhDAeIaoy\nkmnwUsUCVuiEwfhyjH8FjSn+AMZYnNC7+urlFJthwQKBgQDhL5mXo7YKwRNklEyB\nVrS4heE2MTpU08tisxCpfHMadJubD6w2v9z9gVOVkENf1CxNE8qIp4OhfvqacHPM\ndX1tX+/eF09/brctxKZVtNEhryKPXV1zXFYgQvbetUnUp44Nck/1j9tYWVISJ+Ss\nJu/rmVulvWFg9Z1zR5X8W0+aaQKBgQD2sJPPeTll+u4HPHRE6i0pZx6saY2Cqv9g\nWCgpDlh0s/XVASxj70hiupGqhd27m3kfSLXkl1s0xEnZ7LS8yVWdFqf8cal8Xq81\n/wD5bBUYgR8+OgYQ0dj1gJkWkChXZNSL2zN8hDzhL2+ECnpxYH6dEgAdjay2+Jan\n80R28z6WuwKBgEDkfLiMPvueZD5J1jo3iGDcg+ggC5VCa4wH2jddW7Y2AFmRDKnC\nZKbRTAr/xcqp1BJqL6Vt0KsLcqBq45P6D6kjSnaP9SLd/v+7ecudDd9NHwJ9f16t\nL0ygv4+yYpJbrr4FQTGcwTMWmmYNBQLvPZiBWz3J83QDk9oSuRA+KBRxAoGBAIwD\nqtFOP6rHIoSO5nsa4ukl8z3uZvgsL+gyARFUaBZM8hGkqdpKvK30sKq1ciWCV9vO\nvBZzZbvsUPJUrDyelW4kptHcfVLutsmR466tjsequd3qtvii8l5dUAaDabI4s35x\nuqZIs/knoEa0X8yr9REXX2NmvwnWzEOlCk3tP6/zAoGAIdtk+pzDXExCcZMgcDYn\nf0FY1vjaqkIDhnG2HRZ2/qHcgyVUKomysPXB9FgfsR5BY+fFokXbi+IpUfJ5KHw5\njHQlmxHLKDBUoCU54IJDPYM61eZHwZQdDvWwbFwFJgkuXAKE901ZwJAEu/0n62zX\nTWYB5RTXtdKwfBgPHhhETQM=\n-----END PRIVATE KEY-----\n";

echo "<pre>\n";

/*** Verify HTTP Signature of request ***/

/*
 * Responsibilities out-of-scope of this example:
 *   - Extract keyId from Signature header (you can use parse_signature_params())
 *   - With the keyId, fetch the respective actor object, to get the public key; you can cache the actor
 *   - Verify the 'Host' header actually matches a domain that the service is authoritative for
 *   - Verify the hostname of the keyId matches the hostname of the actor ID referenced in the POSTed JSON content
 */
echo '<div style="color: #444">';
print_r($request);
echo '</div>';

$result = verify_request_signature($request, $actor_pubkey, $time, true);

if (true === $result) {
    echo "Result: <strong>Signature passes validation</strong>\n";
} else {
    echo "Result: <strong>". sig_errormsg($result)."</strong>\n";
}

echo "\n----\n";

// Sign an HTTP request
$method = 'POST';
$url = 'https://mastodon.example/inbox';
$body = "{\"type\":\"Create\",\"object\":{\"type\":\"Note\",\"content\":\"A quick post.\",\"actor\":\"https://merp.example/users/test\",\"attributedTo\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"sensitive\":false,\"summary\":\"\",\"id\":\"https://merp.example/users/test/posts/2402/11/104046\"},\"actor\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"@context\":[\"https://www.w3.org/ns/activitystreams\"],\"id\":\"https://merp.example/users/test/posts/2402/11#Create-BlyKQu\"}";
$contenttype = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"';

$output = sign_request($actor_privkey, $actor_keyid, $time, $method, $url, $body, $contenttype);
if (is_array($output)) {
    echo "\nSigned headers generated: \n";
    htmlentities(print_r($output));
} else {
    echo "\nError during signing: ".sig_errormsg($output);
}

echo "\n----\n";
$new_request = [
    "method" => $method,
    "path" => parse_url($url, PHP_URL_PATH),
    "headers" => $output,
    "body" => $body,
];

echo '<div style="color: #444">';
print_r($new_request);
echo '</div>';
echo "\nLet's verify what we just signed:\n";
$result = verify_request_signature($request, $actor_pubkey, $time, true);

if (true === $result) {
    echo "Result: <strong>Signature passes validation</strong>\n";
} else {
    echo "Result: <strong>". sig_errormsg($result)."</strong>\n";
}
