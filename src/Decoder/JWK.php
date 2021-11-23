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
    

    /**
     * Get the value with a specific key.
     *
     * @param string $key The key
     *
     * @return null|mixed
     */
    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new InvalidArgumentException(sprintf('The value identified by "%s" does not exist.', $key));
        }

        return $this->values[$key];
    }

    /**
     * Returns true if the JWK has the value identified by.
     *
     * @param string $key The key
     */
    public function has(string $key): bool
    {
        return \array_key_exists($key, $this->values);
    }


}

