<?php

namespace SenNZ\NZCovidPass;

use GuzzleHttp\Exception\InvalidArgumentException;

//Needed to convert the digital signature into an ASN.1 signature (this format is required by OpenSSL)
final class ECSignature
{
    private const ASN1_SEQUENCE = '30';
    private const ASN1_INTEGER = '02';
    private const ASN1_MAX_SINGLE_BYTE = 128;
    private const ASN1_LENGTH_2BYTES = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER = '00';
    private const BYTE_SIZE = 2;

    /**
     * @throws InvalidArgumentException if the length of the signature is invalid
     */
    public static function toAsn1(string $signature, int $length)
    {
        $signature = bin2hex($signature);

        if (self::octetLength($signature) !== $length) {
            throw new InvalidArgumentException('Invalid signature length.');
        }

        $pointR = self::preparePositiveInteger(mb_substr($signature, 0, $length, '8bit'));
        $pointS = self::preparePositiveInteger(mb_substr($signature, $length, null, '8bit'));

        $lengthR = self::octetLength($pointR);
        $lengthS = self::octetLength($pointS);

        $totalLength = $lengthR + $lengthS + self::BYTE_SIZE + self::BYTE_SIZE;
        $lengthPrefix = $totalLength > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';

        $bin = hex2bin(
            self::ASN1_SEQUENCE
            .$lengthPrefix.dechex($totalLength)
            .self::ASN1_INTEGER.dechex($lengthR).$pointR
            .self::ASN1_INTEGER.dechex($lengthS).$pointS
            );
        if (!is_string($bin)) {
            throw new InvalidArgumentException('Unable to parse the data');
        }

        return $bin;
    }
