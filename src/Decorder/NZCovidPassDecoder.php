<?php

namespace SenNZ\NZCovidPass\Decoder;

use Base32\Base32;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use CBOR\OtherObject\OtherObjectManager;
use CBOR\Tag\TagObjectManager;

use SenNZ\NZCovidPass\Decoder\CoseSignTagNZ;
use SenNZ\NZCovidPass\Decoder\JWK;
use SenNZ\NZCovidPass\Decoder\ECSignature;
use SenNZ\NZCovidPass\Decoder\ECKey;

class NZCovidPassDecoder
{
    const JSON = 'json';

    const GET_CERTIFICATE_FROM = 'json';

     public function getVPPdata($raw_data) {
      $data = $this->qrcode($raw_data);

      return $data;
    }


    private function base32($base32)
    {
        try {
          return Base32::decode($base32);
        } catch (\Exception $e) {
          return response()->json([
                'status'  => 'error',
                'message' => '1. Invalid data',
          ]);
        }
    }

    private  function cose($cose)
    {

        $stream = new StringStream($cose);

        $tagObjectManager = new TagObjectManager();
        $tagObjectManager->add(CoseSignTagNZ::class);

        $cborDecoder = new \CBOR\Decoder($tagObjectManager, new OtherObjectManager());

        $cbor = $cborDecoder->decode($stream); // We decode the data


        if (! $cbor instanceof CoseSignTagNZ) {
            //throw new \InvalidArgumentException('Not a valid certificate. Not a CoseSign1 type.');
            return response()->json([
                'status'  => 'error',
                'message' => 'Not a valid certificate. Not a CoseSign1 type',
            ]);
        }


        $list = $cbor->getValue();
        if (! $list instanceof ListObject) {
            //throw new \InvalidArgumentException('Not a valid certificate. No list.');
            return response()->json([
                'status'  => 'error',
                'message' => 'Not a valid certificate. No list',
            ]);
        }

        if (4 !== $list->count()) {
            //throw new \InvalidArgumentException('Not a valid certificate. The list size is not correct.');
            return response()->json([
                'status'  => 'error',
                'message' => 'Not a valid certificate. The list size is not correct',
            ]);
        }
        return $list;
    }
  
    private function cbor($list)
    {
        $decoded = array();
        $tagObjectManager = new TagObjectManager();
        $tagObjectManager->add(CoseSignTagNZ::class);
        $cborDecoder = new \CBOR\Decoder(new TagObjectManager(), new OtherObjectManager());

        $h1 = $list->get(0); // The first item corresponds to the protected header
        $headerStream = new StringStream($h1->getValue()); // The first item is also a CBOR encoded byte string
        $decoded['protected'] = $cborDecoder->decode($headerStream)->getNormalizedData(); // The array [1 => "-7"] = ["alg" => "ES256"]

        $h2 = $list->get(1); // The second item corresponds to unprotected header
        $decoded['unprotected'] = $h2->getNormalizedData(); // The index 4 refers to the 'kid' (key ID) parameter (see https://www.iana.org/assignments/cose/cose.xhtml)

        $data = $list->get(2); // The third item corresponds to the data we want to load
        if (! $data instanceof ByteStringObject) {
           throw new \InvalidArgumentException('Not a valid certificate. The payload is not a byte string.');
        }
        $infoStream = new StringStream($data->getValue()); // The third item is a CBOR encoded byte string
        $decoded['data'] = $cborDecoder->decode($infoStream)->getNormalizedData(); // The data we are looking for

        $signature = $list->get(3); // The fourth item is the signature.
                                    // It can be verified using the protected header (first item) and the data (third item)
                                    // And the public key
        if (! $signature instanceof ByteStringObject) {
            throw new \InvalidArgumentException('Not a valid certificate. The signature is not a byte string.');
        }
        $decoded['signature'] = $signature->getNormalizedData(); // The digital signature


        return $decoded;
    }

     // Retrieve from JSON Country/KID
    private function retrieveCertificates()
    {
        // We retrieve the public keys
        $uri = public_path('cert/did.json');

        $is_file_expired = time() - filemtime($uri) > 24 * 3600;

        if ($is_file_expired) {
          $str = $this->retrieveCertificateFromWeb();
          if(!empty($str)){
            $fp = fopen($uri, 'w');
            fwrite($fp, $str);
            fclose($fp);
          } else {
            throw new \InvalidArgumentException('Unable to download did.json');
          }
        }
        // We decode the JSON object we received
        $certificates = json_decode(file_get_contents($uri), true, 512);
        return $certificates;
    }

    private function retrieveCertificateFromWeb()
    {
        // We retrieve the public keys update manullay
        $ch = curl_init('https://nzcp.identity.health.nz/.well-known/did.json');

        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }
    private function validateKid(array $cbor, $certificates)
    {
        $id = $cbor["data"][1];
        $key = $cbor['protected'][4];
        $cbor_assertion = $id . "#" . $key;

        $cert_assertion = $certificates["assertionMethod"][0];


        if ($cbor_assertion != $cert_assertion) {
            throw new \InvalidArgumentException('Invalid KID');
        }

        $pk = $certificates["verificationMethod"][0]["publicKeyJwk"];

        return $pk;
    }
    public function qrcode(string $qrcode)
    {
        if (! substr($qrcode, 0, 5) === 'NZCP:') {
            throw new \InvalidArgumentException('Invalid NZCP Header');
        }

        if (!preg_match("/NZCP:\/\d\//",$qrcode)) {
            throw new \InvalidArgumentException('Invalid NZCP Header/Version');
        }

        $b32 = $this->base32(mb_substr($qrcode, 8));


        $cose = $this->cose($b32);
        //$cose = $this->cose($this->zlib($zlib));
        $cbor = $this->cbor($cose);

        $expiry = isset($cbor["data"][4]) ? $cbor["data"][4] : 0;
        if ($expiry < time()) {
            throw new InvalidArgumentException('Expired pass');
        }

        $certificateKeys = array();

        $pem = "";

        if (static::GET_CERTIFICATE_FROM == static::JSON) {
            $certificates = static::retrieveCertificates();
            $signingCertificate = static::validateKid($cbor, $certificates);

            if (isset($signingCertificate->original["status"]) && $signingCertificate->original["status"]=="error") {
              throw new InvalidArgumentException('Invalid KID');
            }

            $jwk = new JWK($signingCertificate);
            $ec_key = new ECKey;
            $pem = $ec_key->convertToPEM($jwk);
        }


        // The object is the data that should have been signed
        $structure = new ListObject();
        $structure->add(new TextStringObject('Signature1'));
        $header = $cose->get(0);
        if (!$header instanceof ByteStringObject) {
            throw new InvalidArgumentException('Invalid COSE header');
        }
        $structure->add($header);
        $structure->add(new ByteStringObject(''));
        $payload = $cose->get(2);
        if (!$payload instanceof ByteStringObject) {
            throw new InvalidArgumentException('Invalid COSE payload');
        }
        $structure->add($payload);

        // Converted signature
        $derSignature = ECSignature::toAsn1($cbor['signature'], 64);

        $pkey  = openssl_pkey_get_public($pem);

        $isValid = openssl_verify((string) $structure, $derSignature, $pkey, OPENSSL_ALGO_SHA256);


        if ($isValid != 1) {
            while ($m = openssl_error_string()) {
               //to debug
               //static::dump("OpenSSL Error ", $m);
            }
            throw new \InvalidArgumentException('The signature is NOT valid');
        }

        return $cbor['data']["vc"]["credentialSubject"];
    }
}
                                          
  
  
