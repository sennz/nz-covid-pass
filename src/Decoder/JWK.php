<?php
namespace SenNZ\NZCovidPass\Decoder;

use Base64Url\Base64Url;
use InvalidArgumentException;
use JsonSerializable;

class JWK implements JsonSerializable
{
    /**
     * @var array
     */
    private $values = [];

    /**
     * Creates a JWK object using the given values.
     * The member "kty" is mandatory. Other members are NOT checked.
     */
    public function __construct(array $values)
    {
        if (!isset($values['kty'])) {
            throw new InvalidArgumentException('The parameter "kty" is mandatory.');
        }
        $this->values = $values;
    }


    /**
     * Returns the values to be serialized.
     */
    public function jsonSerialize(): array
    {
        return $this->values;
    }

}

