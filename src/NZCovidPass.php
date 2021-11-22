<?php

namespace SenNZ\NZCovidPass;

use SenNZ\NZCovidPass\Decoder\NZCovidPassDecoder;

class NZCovidPass {
   public function __construct($raw_data) {
     try {
       $decoder = new NZCovidPassDecoder;
       $data = $decoder->getNZPassData($raw_data);
       return $data;
     } catch (\Exception $e) {
       throw new \InvalidArgumentException('Invalid data');  
     }
   }
}
