<?php

namespace SenNZ\NZCovidPass;

use SenNZ\NZCovidPass\Decoder\NZCovidPassDecoder;

class NZCovidPass {
   
   public $data;
   
   public function __construct($raw_data,$path="") {
     try {
       $decoder = new NZCovidPassDecoder;
       $data = $decoder->getNZPassData($raw_data,$path);
       $this->data = $data;
     } catch (\Exception $e) {
       throw new \InvalidArgumentException('Invalid data');  
     }
   }
   
   public function getNZPassData() {
     return $this->data;
   }

}
