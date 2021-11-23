# NZ-COVID-Pass
NZ COVID Pass PHP SDK

It is based on Ministry of Health technical specification

https://nzcp.covid19.health.nz/

<b>Requirement</b>
PHP >= 7.2 

<b>Usage</b>

<code>\n
$pass = new NZCovidPass($strQRCode,$path_to_save_did_file);
  \n
$data = $pass->getNZPassData();\n
</code>

$strQRCode - Covid Pass QR Code Data<br/>
$path_to_save_did_file - <br/>
Path to save did.json file, it is optional, if you don't provide the path, it will use the local file.
Path should have the write permission to web root
<br/><br/>
Thanks to the contribution
<a href="https://github.com/DevPGS" target="_a">DevPGS</a> and
<a href="https://github.com/herald-si" target="_a">herald-si</a> 


<b>Privacy</b><br/>
Please refer https://github.com/minhealthnz/nzcovidpass-spec
