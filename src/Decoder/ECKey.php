<?php
namespace SenNZ\NZCovidPass\Decoder;

use function extension_loaded;
use InvalidArgumentException;
use function is_array;
use SenNZ\NZCovidPasss\JWK;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;


class ECKey
{
    public static function convertToPEM(JWK $jwk): string
    {
        return self::convertPublicKeyToPEM($jwk);
    }

    /**
     * @throws InvalidArgumentException if the curve is not supported
     */
    public static function convertPublicKeyToPEM(JWK $jwk): string
    {
        switch ($jwk->get('crv')) {
            case 'P-256':
                $der = self::p256PublicKey();

                break;
            default:
                throw new InvalidArgumentException('Unsupported curve.');
        }
        $der .= self::getKey($jwk);
        $pem = '-----BEGIN PUBLIC KEY-----'.PHP_EOL;
        $pem .= chunk_split(base64_encode($der), 64, PHP_EOL);
        $pem .= '-----END PUBLIC KEY-----'.PHP_EOL;

        return $pem;
    }


    private static function p256PublicKey(): string
    {
        return pack(
            'H*',
            '3059' // SEQUENCE, length 89
                .'3013' // SEQUENCE, length 19
                    .'0607' // OID, length 7
                        .'2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                    .'0608' // OID, length 8
                        .'2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
                .'0342' // BIT STRING, length 66
                    .'00' // prepend with NUL - pubkey will follow
        );
    }
  
    private static function getKey(JWK $jwk): string
    {
        $nistCurveSize = self::getNistCurveSize($jwk->get('crv'));
        $length = (int) ceil($nistCurveSize / 8);

        return
            "\04"
            .str_pad(Base64UrlSafe::decode($jwk->get('x')), $length, "\0", STR_PAD_LEFT)
            .str_pad(Base64UrlSafe::decode($jwk->get('y')), $length, "\0", STR_PAD_LEFT);
    }


}
