<?php

/*
CertSage (support@griffin.software)
Copyright 2021 Griffin Software (https://griffin.software)

PHP 7.0+ required

Permission is granted to distribute this software in its original form.
Permission is denied to distribute any works derived from this software.
No guarantees or warranties of any kind are made as to the fitness of this software for any purpose.
Usage of this software constitutes acceptance of full liability for any consequences resulting from its usage.
*/

$version = "1.1.0";
$dataDirectory = "../CertSage";

class CertSage
{
  private $dataDirectory = null;
  private $responses = [];
  private $acmeDirectory = null;
  private $accountKey = null;
  private $accountUrl = null;

  private function createDirectory($directoryPath, $permissions)
  {
    clearstatcache(true, $directoryPath);

    if (file_exists($directoryPath))
      return;

    if (!mkdir($directoryPath, $permissions))
      throw new Exception("could not create directory: $directoryPath");
  }

  private function readFile($filePath)
  {
    clearstatcache(true, $filePath);

    if (!file_exists($filePath))
      return null;

    $string = file_get_contents($filePath);

    if ($string === false)
      throw new Exception("could not read file: $filePath");

    return $string;
  }

  private function writeFile($filePath, $string, $permissions)
  {
    if (file_put_contents($filePath, $string, LOCK_EX) === false)
      throw new Exception("could not write file: $filePath");

    if (!chmod($filePath, $permissions))
      throw new Exception("could not set permissions for file: $filePath");
  }

  private function deleteFile($filePath)
  {
    clearstatcache(true, $filePath);

    if (!file_exists($filePath))
      return;

    if (!unlink($filePath))
      throw new Exception("could not delete file: $filePath");
  }

  private function encodeJSON($data)
  {
    $string = json_encode($data, JSON_UNESCAPED_SLASHES);

    if (json_last_error() != JSON_ERROR_NONE)
      throw new Exception("encode JSON failed");

    return $string;
  }

  private function decodeJSON($string)
  {
    $data = json_decode($string, true);

    if (json_last_error() != JSON_ERROR_NONE)
      throw new Exception("decode JSON failed");

    return $data;
  }

  private function encodeBase64($string)
  {
    return strtr(rtrim(base64_encode($string), "="), "+/", "-_");
  }

  private function decodeBase64($base64)
  {
    // consider strict mode to handle non-Base64 characters
    return base64_decode(strtr($base64, "-_", "+/"));
  }

  private function findHeader($response, $target, $required = true)
  {
    $regex = "~^$target: ([^\r\n]+)[\r\n]*$~i";
    foreach ($response["headers"] as $header)
    {
      $outcome = preg_match($regex, $header, $matches);

      if ($outcome === false)
        throw new Exception("regular expression match failed when extracting header");

      if ($outcome === 1)
        return $matches[1];
    }

    if ($required)
      throw new Exception("missing $target header");

    return null;
  }

  // singleton required due to static nonce?
  private function sendRequest($url, $expectedResponseCode, $payload = null, $jwk = null)
  {
    static $nonce = null;
    $headers = [];
    $headerSize = 0;

    $ch = curl_init($url);

    if ($ch === false)
      throw new Exception("cURL initialization failed");

    if (!curl_setopt($ch, CURLOPT_USERAGENT, "CertSage/" . $this->version . " (support@griffin.software)"))
      throw new Exception("cURL set user agent option failed");

    if (!curl_setopt($ch, CURLOPT_RETURNTRANSFER, true))
      throw new Exception("cURL set return transfer option failed");

    if (isset($payload))
    {
      if (!isset($nonce))
      {
        $response = $this->sendRequest($this->acmeDirectory["newNonce"], 204);

        if (!isset($nonce))
          throw new Exception("get new nonce failed");
      }

      $protected = [
        "url"   => $url,
        "alg"   => "RS256",
        "nonce" => $nonce
      ];

      if (isset($jwk))
        $protected["jwk"] = $jwk;
      else
        $protected["kid"] = $this->accountUrl;

      $protected = $this->encodeBase64($this->encodeJSON($protected));
      $payload   =   $payload === ""
                   ? ""
                   : $this->encodeBase64($this->encodeJSON($payload));

      if (openssl_sign("$protected.$payload", $signature, $this->accountKey, "sha256WithRSAEncryption") === false)
        throw new Exception("openssl sign failed");

      $signature = $this->encodeBase64($signature);

      $josejson = $this->encodeJSON([
        "protected" => $protected,
        "payload"   => $payload,
        "signature" => $signature
      ]);

      if (!curl_setopt($ch, CURLOPT_POSTFIELDS, $josejson))
        throw new Exception("cURL set post fields option failed");

      if (!curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/jose+json", "Content-Length: " . strlen($josejson)]))
        throw new Exception("cURL set http header option failed");
    }

    if (!curl_setopt($ch, CURLOPT_HEADER, true))
      throw new Exception("cURL set header option failed");

    if (!curl_setopt($ch, CURLOPT_HEADERFUNCTION,
           function($ch, $header) use (&$headers, &$headerSize)
           {
             $headers[] = $header;
             $length = strlen($header);
             $headerSize += $length;
             return $length;
           }))
      throw new Exception("cURL set header function option failed");

    $body = curl_exec($ch);

    if ($body === false)
      throw new Exception("cURL execution failed: $url");

    $this->responses[] = $body;

    $responseCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

    if ($responseCode === false)
      throw new Exception("cURL get response code info failed");

    /*
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);

    if ($headerSize === false)
      throw new Exception("cURL get header size info failed");
    */

    $length = strlen($body);

    if ($headerSize > $length)
      throw new Exception("improper response header size");

    $body =   $headerSize == $length
            ? ""
            : substr($body, $headerSize);

    if ($body === false)
      throw new Exception("could not truncate headers from response");

    $response = [
      "headers" => $headers,
      "body"    => $body
    ];

    if ($responseCode !== $expectedResponseCode)
    {
      if ($this->findHeader($response, "content-type", false) === "application/problem+json")
      {
        $problem = $this->decodeJSON($response["body"]);

        if (isset($problem["type"], $problem["detail"]))
          throw new Exception($problem["type"] . ": " . $problem["detail"]);
      }

      throw new Exception("unexpected response code: $responseCode vs $expectedResponseCode");
    }

    $nonce = $this->findHeader($response, "replay-nonce", false);

    return $response;
  }

  public function dumpResponses($fileName)
  {
    $this->writeFile($this->dataDirectory . "/$fileName",
                     implode("\n\n-----\n\n", array_reverse($this->responses)),
                     0600);
  }

  public function __construct($version, $dataDirectory, $code = null)
  {
    // *** SET VERSION ***

    $this->version = $version;

    // *** CREATE DATA DIRECTORY ***

    $this->createDirectory($dataDirectory, 0700);

    $this->dataDirectory = $dataDirectory;

    $filePath = $dataDirectory . "/code.txt";

    try
    {
      if (isset($code))
      {
        // *** CHECK CODE ***

        $correctCode = $this->readFile($filePath);

        if (!isset($correctCode))
          throw new Exception("code.txt was missing");

        if ($code !== $correctCode)
          throw new Exception("code was incorrect");
      }
    }
    finally
    {
      // *** UPDATE CODE ***

      $this->writeFile($filePath,
                       $this->encodeBase64(random_bytes(12)),
                       0600);
    }
  }

  public function execute($environment, $emailAddresses, $domainNames)
  {
    // *** ESTABLISH ENVIRONMENT ***

    switch ($environment)
    {
      case "production":

        $filePath = $this->dataDirectory . "/account.key";
        $url = "https://acme-v02.api.letsencrypt.org/directory";

        break;

      case "staging":

        $filePath = $this->dataDirectory . "/account-staging.key";
        $url = "https://acme-staging-v02.api.letsencrypt.org/directory";

        break;

      default:

        throw new Exception("unknown environment");
    }

    // *** READ ACCOUNT KEY ***

    $this->accountKey = $this->readFile($filePath);

    $accountKeyExists = isset($this->accountKey);

    if ($accountKeyExists)
    {
      // *** CHECK ACCOUNT KEY ***

      $accountKeyObject = openssl_pkey_get_private($this->accountKey);

      if ($accountKeyObject === false)
        throw new Exception("check account key failed");
    }
    else
    {
      // *** GENERATE ACCOUNT KEY ***

      $options = [
        "digest_alg"       => "sha256",
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA
      ];

      $accountKeyObject = openssl_pkey_new($options);

      if ($accountKeyObject === false)
        throw new Exception("generate account key failed");

      if (!openssl_pkey_export($accountKeyObject, $this->accountKey))
        throw new Exception("export account key failed");
    }

    // *** GET ACCOUNT KEY DETAILS ***

    $accountKeyDetails = openssl_pkey_get_details($accountKeyObject);

    if ($accountKeyDetails === false)
      throw new Exception("get account key details failed");

    // *** CONSTRUCT JWK ***

    $jwk = [
      "e" => $this->encodeBase64($accountKeyDetails["rsa"]["e"]), // public exponent
      "kty" => "RSA",
      "n" => $this->encodeBase64($accountKeyDetails["rsa"]["n"])  // modulus
    ];

    // *** CALCULATE THUMBPRINT ***

    $digest = openssl_digest($this->encodeJSON($jwk), "sha256", true);

    if ($digest === false)
      throw new Exception("digest JWK failed");

    $thumbprint = $this->encodeBase64($digest);

    // *** GET ACME DIRECTORY ***

    $response = $this->sendRequest($url, 200);

    $this->acmeDirectory = $this->decodeJSON($response["body"]);

    if ($accountKeyExists)
    {
      // *** LOOKUP ACCOUNT ***

      $url = $this->acmeDirectory["newAccount"];

      $payload = [
        "onlyReturnExisting" => true
      ];

      $response = $this->sendRequest($url, 200, $payload, $jwk);
    }
    else
    {
      // *** REGISTER ACCOUNT ***

      $url = $this->acmeDirectory["newAccount"];

      $payload = [
        "termsOfServiceAgreed" => true
      ];

      $response = $this->sendRequest($url, 201, $payload, $jwk);

      // *** WRITE ACCOUNT KEY ***

      $this->writeFile($filePath,
                       $this->accountKey,
                       0600);
    }

    $this->accountUrl = $this->findHeader($response, "location");

    // *** UPDATE CONTACT ***

    $url = $this->accountUrl;

    $contact = [];

    foreach ($emailAddresses as $emailAddress)
      $contact[] = "mailto:$emailAddress";

    $payload = [
      "contact" => $contact
    ];

    $response = $this->sendRequest($url, 200, $payload);

    // *** STOP IF NO DOMAIN NAMES SUBMITTED ***

    if (empty($domainNames))
      return;

    // *** CREATE NEW ORDER ***

    $url = $this->acmeDirectory["newOrder"];

    $identifiers = [];

    foreach ($domainNames as $domainName)
      $identifiers[] = [
        "type"  => "dns",
        "value" => $domainName
      ];

    $payload = [
      "identifiers" => $identifiers
    ];

    $response = $this->sendRequest($url, 201, $payload);

    $orderurl = $this->findHeader($response, "location");
    $order = $this->decodeJSON($response["body"]);

    // *** GET CHALLENGES ***

    $authorizationurls = [];
    $challengeurls = [];
    $challengetokens = [];

    $payload = ""; // empty

    foreach ($order["authorizations"] as $url)
    {
      $response = $this->sendRequest($url, 200, $payload);

      $authorization = $this->decodeJSON($response["body"]);

      if ($authorization["status"] === "valid")
        continue;

      $authorizationurls[] = $url;

      foreach ($authorization["challenges"] as $challenge)
      {
        if ($challenge["type"] !== "http-01")
          continue;

        $challengeurls[] = $challenge["url"];
        $challengetokens[] = $challenge["token"];
        continue 2;
      }

      throw new Exception("no http-01 challenge found");
    }

    // *** WRITE HTTP-01 CHALLENGE FILES ***

    $this->createDirectory("./.well-known", 0755);
    $this->createDirectory("./.well-known/acme-challenge", 0755);

    try
    {
      foreach ($challengetokens as $challengetoken)
        $this->writeFile("./.well-known/acme-challenge/$challengetoken",
                         "$challengetoken.$thumbprint",
                         0644);

      // *** CONFIRM CHALLENGES ***

      sleep(2);

      $payload = (object)[]; // empty object

      foreach ($challengeurls as $url)
        $challenge = $this->sendRequest($url, 200, $payload);

      // *** CHECK AUTHORIZATIONS ***

      $payload = ""; // empty

      foreach ($authorizationurls as $url)
      {
        for ($attempt = 1; true; ++$attempt)
        {
          sleep(1);

          $response = $this->sendRequest($url, 200, $payload);

          $authorization = $this->decodeJSON($response["body"]);

          if ($authorization["status"] !== "pending")
            break;

          if ($attempt == 10)
            throw new Exception("authorization still pending after $attempt attempts");
        }

        if ($authorization["status"] !== "valid")
          throw new Exception("authorization failed");
      }
    }
    finally
    {
      // *** DELETE HTTP-01 CHALLENGE FILES ***

      foreach ($challengetokens as $challengetoken)
        $this->deleteFile("./.well-known/acme-challenge/$challengetoken");
    }

    // *** GENERATE CERTIFICATE KEY ***

    $options = [
      "digest_alg"       => "sha256",
      "private_key_bits" => 2048,
      "private_key_type" => OPENSSL_KEYTYPE_RSA
    ];

    $certificateKeyObject = openssl_pkey_new($options);

    if ($certificateKeyObject === false)
      throw new Exception("generate certificate key failed");

    if (!openssl_pkey_export($certificateKeyObject, $certificateKey))
      throw new Exception("export certificate key failed");

    // *** GENERATE CSR ***

    $dn = [
      "commonName" => $domainNames[0]
    ];

    $options = [
      "digest_alg" => "sha256",
      "config" => $this->dataDirectory . "/openssl.cnf"
    ];

    $opensslcnf =
      "[req]\n" .
      "distinguished_name = req_distinguished_name\n" .
      "req_extensions = v3_req\n\n" .
      "[req_distinguished_name]\n\n" .
      "[v3_req]\n" .
      "subjectAltName = @san\n\n" .
      "[san]\n";

    $i = 0;
    foreach ($domainNames as $domainName)
    {
      ++$i;
      $opensslcnf .= "DNS.$i = $domainName\n";
    }

    try
    {
      $this->writeFile($this->dataDirectory . "/openssl.cnf",
                       $opensslcnf,
                       0600);

      $csrObject = openssl_csr_new($dn, $certificateKey, $options);

      if ($csrObject === false)
        throw new Exception("generate csr failed");
    }
    finally
    {
      $this->deleteFile($this->dataDirectory . "/openssl.cnf");
    }

    if (!openssl_csr_export($csrObject, $csr))
      throw new Exception("export csr failed");

    // *** FINALIZE ORDER ***

    $url = $order["finalize"];

    $regex = "~^-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+/]+)=?=?-----END CERTIFICATE REQUEST-----$~";
    $outcome = preg_match($regex, str_replace("\n", "", $csr), $matches);

    if ($outcome === false)
      throw new Exception("extract csr failed");

    if ($outcome === 0)
      throw new Exception("csr format mismatch");

    $payload = [
      "csr" => strtr($matches[1], "+/", "-_")
    ];

    $response = $this->sendRequest($url, 200, $payload);

    $order = $this->decodeJSON($response["body"]);

    if ($order["status"] !== "valid")
    {
      // *** CHECK ORDER ***

      $url = $orderurl;

      $payload = ""; // empty

      for ($attempt = 1; true; ++$attempt)
      {
        sleep(1);

        $response = $this->sendRequest($url, 200, $payload);

        $order = $this->decodeJSON($response["body"]);

        if (!(   $order["status"] === "pending"
              || $order["status"] === "processing"
              || $order["status"] === "ready"))
          break;

        if ($attempt == 10)
          throw new Exception("order still pending after $attempt attempts");
      }

      if ($order["status"] !== "valid")
        throw new Exception("order failed");
    }

    // *** DOWNLOAD CERTIFICATE ***

    $url = $order["certificate"];

    $payload = ""; // empty

    $response = $this->sendRequest($url, 200, $payload);

    $certificate = $response["body"];

    // *** WRITE CERTIFICATE AND KEY ***

    $this->writeFile($this->dataDirectory . "/certificate.crt",
                     $certificate,
                     0600);

    $this->writeFile($this->dataDirectory . "/certificate.key",
                     $certificateKey,
                     0600);
  }
}

try
{
  // *** PROCESS ACTION ***

  if (!isset($_POST["action"]))
    $action = "";
  else
  {
    if (!is_string($_POST["action"]))
      throw new Exception("action was not a string");

    $action = $_POST["action"];
  }

  switch ($action)
  {
    case "":

      // *** CREATE DATA DIRECTORY AND UPDATE CODE ***

      $certsage = new CertSage($version, $dataDirectory);

      $page = "welcome";

      break;

    case "proceed":

      // *** PROCESS CODE ***

      if (!isset($_POST["code"]))
        throw new Exception("code was missing");

      if (!is_string($_POST["code"]))
        throw new Exception("code was not a string");

      $code = $_POST["code"];

      // *** CREATE DATA DIRECTORY, CHECK CODE, AND UPDATE CODE ***

      $certsage = new CertSage($version, $dataDirectory, $code);

      // *** PROCESS ENVIRONMENT ***

      if (!isset($_POST["environment"]))
        throw new Exception("environment was missing");

      if (!is_string($_POST["environment"]))
        throw new Exception("environment was not a string");

      $environment = $_POST["environment"];

      // *** PROCESS EMAIL ADDRESSES ***

      if (!isset($_POST["emailAddresses"]))
        throw new Exception("emailAddresses was missing");

      if (!is_string($_POST["emailAddresses"]))
        throw new Exception("emailAddresses was not a string");

      $emailAddresses = [];

      for ($tok = strtok($_POST["emailAddresses"], "\r\n"); $tok !== false; $tok = strtok("\r\n"))
      {
        $tok = trim($tok);

        if (strlen($tok) == 0)
          continue;

        $emailAddresses[] = $tok;
      }

      // *** PROCESS DOMAIN NAMES ***

      if (!isset($_POST["domainNames"]))
        throw new Exception("domainNames was missing");

      if (!is_string($_POST["domainNames"]))
        throw new Exception("domainNames was not a string");

      $domainNames = [];

      for ($tok = strtok($_POST["domainNames"], "\r\n"); $tok !== false; $tok = strtok("\r\n"))
      {
        $tok = trim($tok);

        if (strlen($tok) == 0)
          continue;

        $domainNames[] = $tok;
      }

      // *** EXECUTE ***

      $certsage->execute($environment, $emailAddresses, $domainNames);

      $page = "success";

      break;

    default:

      throw new Exception("unknown action");
  }
}
catch (Exception $e)
{
  $error = $e->getMessage();

  $page = "trouble";
}
finally
{
  if (isset($certsage))
    $certsage->dumpResponses("responses.txt");
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CertSage</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#e1b941">
<meta name="referrer" content="origin">
</script>
<style>
*
{
  box-sizing: border-box;
  outline: none;
  margin: 0;
  border: none;
  padding: 0;
}

html
{
  background: #4169e1;
  font: 100%/1.5 sans-serif;
  color: black;
}

body
{
  margin: auto;
  max-width: 34rem;
  padding: 1.5rem;
}

header, main, footer, article, section,
h1, h2, h3, h4, h5, h6, p, form
{
  margin-bottom: 1.5rem;
}

:last-child
{
  margin-bottom: 0;
}

header, article
{
  border-radius: 1.5rem;
  padding: 1.5rem;
  background: rgba(255,255,255,0.80);
}

header
{
  text-align: center;
}

header > span
{
  font-size: 2rem;
  font-family: fantasy;
}

header a
{
  text-decoration: none;
  color: inherit;
}

footer
{
  text-align: center;
  color: rgba(255,255,255,0.80);
}

footer a
{
  color: inherit;
}

h1, h2, h3, h4, h5, h6
{
  text-align: center;
  font-weight: normal;
  line-height: 1.25;
}

h1
{
  font-size: calc(24rem / 12);
}

h2
{
  font-size: calc(18rem / 12);
}

h3
{
  font-size: calc(14rem / 12);
}

h4
{
  font-size: calc(16rem / 12);
}

h5
{
  font-size: calc(10rem / 12);
}

h6
{
  font-size: calc(8rem / 12);
}

a
{
  -webkit-tap-highlight-color: transparent;
}

form
{
  text-align: center;
}

label
{
  font-size: calc(18rem / 12);
}

textarea, input[type=text]
{
  display: inline-block;
  margin-top: 0.75rem;
  box-shadow: 0 0 0.375rem 0 black;
  width: 100%;
  border-radius: 0.75rem;
  padding: 0.75rem;
  resize: none;
  background: white;
  font: inherit;
  color: inherit;
}

textarea
{
  text-align: left;
}

input[type=text]
{
  text-align: center;
}

input[type=radio]
{
  display: none;
}

input[type=radio] + span, button
{
  display: inline-block;
  margin: 0.75rem 0.375rem 0;
  box-shadow: 0 0 0.375rem 0 black;
  border: 0.1875rem solid rgba(0,0,0,0.25);
  border-radius: 0.75rem;
  padding: 0.75rem;
  background: lightgray;
  font-size: 1rem;
  line-height: 1;
}

button
{
  -webkit-tap-highlight-color: transparent;
  font: inherit;
  color: inherit;
}

input[type=radio]:checked + span, button:active
{
  box-shadow: 0 0 0.375rem 0 black inset;
  border: 0.1875rem solid rgba(0,0,0,0.50);
  font-weight: bold;
}
</style>
</head>
<body>

<header>
<span>&#x1F9D9;&#x1F3FC;&#x200D;&#x2642;&#xFE0F; CertSage</span><br>
version <?= $version ?><br>
<a href="mailto:support@griffin.software">support@griffin.software</a>
</header>

<main>
<article>
<?php switch ($page):
  case "welcome": ?>

<h1>Welcome!</h1>

<p>CertSage is an <a href="https://tools.ietf.org/html/rfc8555" target="_blank">ACME</a> client that acquires free <a href="https://en.m.wikipedia.org/wiki/Domain-validated_certificate" target="_blank">DV certificates</a> from <a href="https://letsencrypt.org/about/" target="_blank">Let's Encrypt</a> by satisfying an <a href="https://letsencrypt.org/docs/challenge-types/#http-01-challenge" target="_blank">HTTP-01 challenge</a> for each <a href="https://en.m.wikipedia.org/wiki/Domain_name" target="_blank">domain name</a> to be covered by a certificate.</p>

<form autocomplete="off" method="post" onsubmit="document.getElementById('proceed').innerHTML = 'Processing...';">
<label>Code</label><br>
Contents of this file:<br>
<?= $dataDirectory . "/code.txt" ?><br>
<input name="code" type="text"><br>
<br>
<label>Environment</label><br>
Please test using the <a href="https://letsencrypt.org/docs/staging-environment/" target="_blank">staging environment</a><br>
to avoid hitting the <a href="https://letsencrypt.org/docs/rate-limits/" target="_blank">rate limits</a><br>
<label><input name="environment" value="staging" type="radio"><span>Staging</span></label> <label><input name="environment" value="production" type="radio" checked><span>Production</span></label><br>
<br>
<label>Email Addresses</label><br>
Only for Let's Encrypt notifications<br>
One per line<br>
<textarea name="emailAddresses" rows="5"></textarea><br>
<br>
<label>Domain Names</label><br>
No wildcards (*)<br>
One per line<br>
<textarea name="domainNames" rows="5"></textarea><br>
<br>
<label>Subscriber Agreement</label><br>
By proceeding you are agreeing to the<br>
<a href="https://letsencrypt.org/repository/" target="_blank">Let's Encrypt Subscriber Agreement</a><br>
<button id="proceed" name="action" value="proceed" type="submit">Proceed</button>
</form>

<?php break;
  case "success": ?>

<h1>Success!</h1>

<?php switch ($environment):
    case "production": ?>

<p>If you submitted any fully qualified domain names, your new certificate and its key have been saved in <?= $dataDirectory ?>.</p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>

<p><a href="">Click here to start over.</a></p>

<?php break;
    case "staging": ?>

<p>Your test using the <a href="https://letsencrypt.org/docs/staging-environment/" target="_blank">staging environment</a> was successful.</p>

<p>If you want to acquire a trusted certificate, please use the production environment.</p>

<p><a href="">Click here to start over.</a></p>

<?php break;
    endswitch; ?>

<?php break;
  case "trouble": ?>

<h1>Trouble...</h1>

<p><?= $error ?></p>

<p>If you need help with resolving this issue, please post a topic in the help category of the <a href="https://community.letsencrypt.org/" target="_blank">Let's Encrypt Community</a>.</p>

<p><a href="">Click here to start over.</a></p>

<?php break;
  endswitch; ?>
</article>
</main>

<footer>
<a href="https://venmo.com/code?user_id=3205885367156736024" target="_blank">Donate to @CertSage via Venmo</a><br>
<br>
<a href="https://paypal.me/CertSage" target="_blank">Donate to @CertSage via PayPal</a><br>
<br>
<a href="https://letsencrypt.org/donate/" target="_blank">Donate to Let's Encrypt</a><br>
<br>
&copy; 2021 <a href="https://griffin.software" target="_blank">Griffin Software</a>
</footer>

</body>
</html>