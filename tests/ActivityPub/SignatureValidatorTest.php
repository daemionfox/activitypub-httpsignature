<?php

namespace Tests\ActivityPub;

use AP\ActivityPub\SignatureValidator;
use AP\Exceptions\APSignatureException;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;

class SignatureValidatorTest extends TestCase
{
    protected array $actor;
    protected array $request;
    protected string $privatekey;
    protected string $testTime;

    protected SignatureValidator $validator;

    public function setup(): void
    {
        $this->validator = new SignatureValidator();
        $this->request = [
            "method" => "POST",
            "path" => "/inbox",
            "headers" => [
                "content-type" => "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                "host" => "mastodon.example",
                "date" => "Sun, 11 Feb 2024 10:41:33 GMT",
                "digest" => "SHA-256=sg6O7VE7pAo1a0yE6wdnXQGf13XROKnuUdvHlT6W7Bg=",
                "signature" => "keyId=\"https://merp.example/users/test#main-key\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date digest content-type\",signature=\"Ib4xcWO1UqFBDzPhIHDJMjO8CxVgg27MygsyAW64EL+owBjjTWVou/3B6sUWAFRwX+wV+6ZGEycLyxaH8zKoueulr5ZSv8q+inGleErgwfCcPT3o4tGgaf4dd1GIXcxxw6c0JeRJSJZ9Ie9zi+41Gc7naz9dCA2eXM4XyLx0Ag61x54CFOwgU1P1koyoIOK+mIlsxuf1oizWRnGOXx3voSPL1PrmfXjLmC+wHrg00tuFrLmKEaJaCtjUZCP8Ocq4P9dfJlPkxac844D8fThVuucpY9HUhUz5kHjolDvF80N+m/iW0vdPlC45Yo50XQa6uaQ8ftKfHcEz7N1/A1Sr2g==\""

            ],
    	    "body" => "{\"type\":\"Create\",\"object\":{\"type\":\"Note\",\"content\":\"A quick post.\",\"actor\":\"https://merp.example/users/test\",\"attributedTo\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"sensitive\":false,\"summary\":\"\",\"id\":\"https://merp.example/users/test/posts/2402/11/104046\"},\"actor\":\"https://merp.example/users/test\",\"to\":[\"https://www.w3.org/ns/activitystreams#Public\"],\"cc\":[\"https://merp.example/users/test/followers\"],\"published\":\"2024-02-11T10:40:46Z\",\"@context\":[\"https://www.w3.org/ns/activitystreams\"],\"id\":\"https://merp.example/users/test/posts/2402/11#Create-BlyKQu\"}"
        ];

        $this->actor = [
            "@context" => ["https://www.w3.org/ns/activitystreams"],
            "id" => "https://merp.example/users/test",
            "type" => "Person",
            "inbox" => "https://merp.example/users/test/inbox",
            "outbox" => "https://merp.example/users/test/outbox",
            "preferredUsername" => "test",
            "publicKey" => [
                "id" => "https://merp.example/users/test#main-key",
                "owner" => "https://merp.example/users/test",
                "publicKeyPem" => "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2P8QViTivQI2WXp43RMb\nLtUH4HXSpBb5GP5iMjHddeelWXlMthp/0t3ofU71ZSCMlyAZ2Z383BOPBLyqtWMk\nm7qdonQZCjC6dfUOYuQT3RnW8USruVai2SWKoQbnBkQL9B4zhqHO0HLQDAMWpcwL\nxSlIxV84mbmYw8+5Qwhgt+KZtAfxx2xgLax0PUlPI4dcaI5uOFY7TqmXkr4KQl+Q\nWKpHwsFdhKbm0hZU9Cyk4O5cB9aqOyH583FtJnS4I9kxxlw9kOL9Un8ClX3kc5dQ\n5MzS2YP3PUhmVJolL1zo0gr/SptbsaFrYyw1qdtfYX0U5EmBf/gegKdRVyoWaA1Q\nswIDAQAB\n-----END PUBLIC KEY-----\n"
            ]
        ];
        // This private key is only used for testing and only matches the public key in the actor.  If you're looking to snag someone's private key for other purposes the one won't do you any good.
        $this->privatekey = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDY/xBWJOK9AjZZ\nenjdExsu1QfgddKkFvkY/mIyMd1156VZeUy2Gn/S3eh9TvVlIIyXIBnZnfzcE48E\nvKq1YySbup2idBkKMLp19Q5i5BPdGdbxRKu5VqLZJYqhBucGRAv0HjOGoc7QctAM\nAxalzAvFKUjFXziZuZjDz7lDCGC34pm0B/HHbGAtrHQ9SU8jh1xojm44VjtOqZeS\nvgpCX5BYqkfCwV2EpubSFlT0LKTg7lwH1qo7IfnzcW0mdLgj2THGXD2Q4v1SfwKV\nfeRzl1DkzNLZg/c9SGZUmiUvXOjSCv9Km1uxoWtjLDWp219hfRTkSYF/+B6Ap1FX\nKhZoDVCzAgMBAAECggEAInT+JxpcVsm5z6OUUFFEXmoS13WzfmhCIyc3IzlVLUUc\ntdnTxebsp+iiOPkHcTN7SlQdRrfA+0FafdS9AWiThkGv3lKz1zETABVrChD629Uf\n6IKQXNyA/MeVUn9CGCCeCqRGZ6Pcr1pL5wcRMD/3w9W2adZLqpK/dfh6NpwR9PY0\n+8BsMdOnl1PNVqP8+IsbqUW4AyDP1fuloToU4DXEVTAyBVzXSLKfUyIgFNJIKjum\nsyen2iGJ0o6RmDAHZ56pMhAWmZ8doVYzgfv3t4B0q96XddSpRfCDIUTjhDAeIaoy\nkmnwUsUCVuiEwfhyjH8FjSn+AMZYnNC7+urlFJthwQKBgQDhL5mXo7YKwRNklEyB\nVrS4heE2MTpU08tisxCpfHMadJubD6w2v9z9gVOVkENf1CxNE8qIp4OhfvqacHPM\ndX1tX+/eF09/brctxKZVtNEhryKPXV1zXFYgQvbetUnUp44Nck/1j9tYWVISJ+Ss\nJu/rmVulvWFg9Z1zR5X8W0+aaQKBgQD2sJPPeTll+u4HPHRE6i0pZx6saY2Cqv9g\nWCgpDlh0s/XVASxj70hiupGqhd27m3kfSLXkl1s0xEnZ7LS8yVWdFqf8cal8Xq81\n/wD5bBUYgR8+OgYQ0dj1gJkWkChXZNSL2zN8hDzhL2+ECnpxYH6dEgAdjay2+Jan\n80R28z6WuwKBgEDkfLiMPvueZD5J1jo3iGDcg+ggC5VCa4wH2jddW7Y2AFmRDKnC\nZKbRTAr/xcqp1BJqL6Vt0KsLcqBq45P6D6kjSnaP9SLd/v+7ecudDd9NHwJ9f16t\nL0ygv4+yYpJbrr4FQTGcwTMWmmYNBQLvPZiBWz3J83QDk9oSuRA+KBRxAoGBAIwD\nqtFOP6rHIoSO5nsa4ukl8z3uZvgsL+gyARFUaBZM8hGkqdpKvK30sKq1ciWCV9vO\nvBZzZbvsUPJUrDyelW4kptHcfVLutsmR466tjsequd3qtvii8l5dUAaDabI4s35x\nuqZIs/knoEa0X8yr9REXX2NmvwnWzEOlCk3tP6/zAoGAIdtk+pzDXExCcZMgcDYn\nf0FY1vjaqkIDhnG2HRZ2/qHcgyVUKomysPXB9FgfsR5BY+fFokXbi+IpUfJ5KHw5\njHQlmxHLKDBUoCU54IJDPYM61eZHwZQdDvWwbFwFJgkuXAKE901ZwJAEu/0n62zX\nTWYB5RTXtdKwfBgPHhhETQM=\n-----END PRIVATE KEY-----\n";

        $gmdate = date_create_from_format(DATE_RFC7231, 'Sun, 11 Feb 2024 10:42:39 GMT');
        $this->testTime = intval($gmdate->format('U'));
    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testVerifyRequestSignature()
    {
        $result = $this->validator->verifyRequestSignature($this->request, $this->actor['publicKey']['publicKeyPem'], $this->testTime);
        $this->assertTrue($result);
    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testParseSignatureParams()
    {
        $result = $this->validator->parseSignatureParams($this->request['headers']['signature']);

        $test = [
            "keyId" => "https://merp.example/users/test#main-key",
            "algorithm" => "rsa-sha256",
            "headers" => [
                "(request-target)",
                "host",
                "date",
                "digest",
                "content-type"
            ],
            "signature" => "Ib4xcWO1UqFBDzPhIHDJMjO8CxVgg27MygsyAW64EL+owBjjTWVou/3B6sUWAFRwX+wV+6ZGEycLyxaH8zKoueulr5ZSv8q+inGleErgwfCcPT3o4tGgaf4dd1GIXcxxw6c0JeRJSJZ9Ie9zi+41Gc7naz9dCA2eXM4XyLx0Ag61x54CFOwgU1P1koyoIOK+mIlsxuf1oizWRnGOXx3voSPL1PrmfXjLmC+wHrg00tuFrLmKEaJaCtjUZCP8Ocq4P9dfJlPkxac844D8fThVuucpY9HUhUz5kHjolDvF80N+m/iW0vdPlC45Yo50XQa6uaQ8ftKfHcEz7N1/A1Sr2g=="
        ];
        $this->assertArrayIsEqualToArrayIgnoringListOfKeys($test, $result, []);

    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testVerifyDigest()
    {
        $result = $this->validator->verifyDigest($this->request['headers']['digest'], $this->request['body']);
        $this->assertTrue($result);

    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testVerifySignature()
    {
        $params = $this->validator->parseSignatureParams($this->request['headers']['signature']);

        $result = $this->validator->verifySignature($params,  $this->actor['publicKey']['publicKeyPem'], $this->request['method'], $this->request['path'], $this->request['headers']);
        $this->assertTrue($result);
    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testCanonicalizeHeadersForSig()
    {
        $params = $this->validator->parseSignatureParams($this->request['headers']['signature']);

        $headerList = $params['headers'];
        $result = $this->validator->canonicalizeHeadersForSig($headerList, $this->request['headers']);

        $expected="(request-target): 
host: mastodon.example
date: Sun, 11 Feb 2024 10:41:33 GMT
digest: SHA-256=sg6O7VE7pAo1a0yE6wdnXQGf13XROKnuUdvHlT6W7Bg=
content-type: application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"";

        $this->assertEquals($expected, $result);
    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testVerifyExpiry()
    {
        $params = $this->validator->parseSignatureParams($this->request['headers']['signature']);
        $result = $this->validator->verifyExpiry($this->testTime, $this->request['headers'], $params);
        $this->assertTrue($result);
    }

    /**
     * @covers \AP\ActivityPub\SignatureValidator
     * @covers \AP\ActivityPub\BaseSignature
     */
    public function testSafeSignatureCoverage()
    {
        $params = $this->validator->parseSignatureParams($this->request['headers']['signature']);

        $result = $this->validator->safeSignatureCoverage($params, $this->request['method']);
        $this->assertTrue($result);

    }
}
