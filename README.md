# NZ-COVID-Pass
NZ COVID Pass PHP SDK

It is based on Ministry of Health technical specification

https://nzcp.covid19.health.nz/

Requirement
PHP >= 7.2 

Usage
            
$pass = new NZCovidPass($strQRCode,$path_to_save_did_file);
$data = $pass->getNZPassData();

$strQRCode - Covid Pass QR Code Data
$path_to_save_did_file - 
Path to save did.json file, it is optional, if you don't provide the path, it will use the local file.
Path should have the write permission to web root

Thanks to the contribution
<a href="https://github.com/DevPGS" target="_a">DevPGS</a> and
<a href="https://github.com/herald-si" target="_a">herald-si</a> 


Privacy
Please refer https://github.com/minhealthnz/nzcovidpass-spec
