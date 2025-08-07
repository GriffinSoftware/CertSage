<?php

/*
CertSage (support@griffin.software)
Copyright 2021-2025 Griffin Software (https://griffin.software)

PHP 7.0+ required

Permission is granted to distribute this software in its original form.
Permission is denied to distribute any works derived from this software.
No guarantees or warranties of any kind are made as to the fitness of this software for any purpose.
Usage of this software constitutes acceptance of full liability for any consequences resulting from its usage.
*/

class CertSage
{
  public $version = "2.1.0";
  public $dataDirectory = "../CertSage";
  public $autorenew;
  public $certificateExists;
  public $validFrom;
  public $validTo;
  public $renewAt;
  public $shouldRenewNow;
  public $domainNames;
  public $keyType;

  private $password;
  private $accountKey;
  private $accountUrl;
  private $thumbprint;
  private $nonce;
  private $acmeDirectory;
  private $responses;

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

  private function sendRequest($url, $expectedResponseCode, $payload = null, $jwk = null)
  {
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
      if (!isset($this->nonce))
      {
        $response = $this->sendRequest($this->acmeDirectory["newNonce"], 204);

        if (!isset($this->nonce))
          throw new Exception("get new nonce failed");
      }

      $protected = [
        "url"   => $url,
        "alg"   => "RS256",
        "nonce" => $this->nonce
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
          throw new Exception($problem["type"] . "<br>" . $problem["detail"]);
      }

      throw new Exception("unexpected response code: $responseCode vs $expectedResponseCode");
    }

    $this->nonce = $this->findHeader($response, "replay-nonce", false);

    return $response;
  }

  public function initialize()
  {
    $this->createDirectory($this->dataDirectory, 0755);

    $this->autorenew = $this->readFile($this->dataDirectory . "/autorenew.txt");

    $this->password = $this->readFile($this->dataDirectory . "/password.txt");

    if (!isset($this->password))
    {
      $this->password = $this->encodeBase64(openssl_random_pseudo_bytes(15));

      $this->writeFile($this->dataDirectory . "/password.txt",
                       $this->password,
                       0644);
    }
  }

  public function extractCertificateInfo()
  {
    $certificate = $this->readFile($this->dataDirectory . "/certificate.crt");

    $this->certificateExists = isset($certificate);

    if (!$this->certificateExists)
      return;

    $regex = "~^(-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END CERTIFICATE-----)~";
    $outcome = preg_match($regex, $certificate, $matches);

    if ($outcome === false)
      throw new Exception("extract certificate failed");

    if ($outcome === 0)
      throw new Exception("certificate format mismatch");

    $certificate = $matches[1];

    $certificateObject = openssl_x509_read($certificate);

    if ($certificateObject === false)
      throw new Exception("check certificate failed");

    $certificateData = openssl_x509_parse($certificateObject);

    if ($certificateData === false)
      throw new Exception("parse certificate failed");

    // *** EXTRACT DATES ***

    if (!isset($certificateData["validFrom_time_t"]))
      throw new Exception("validFrom_time_t not found in certificate");

    $validFrom = (int)$certificateData["validFrom_time_t"];

    $this->validFrom = gmdate("M j, Y g:i:s A", $validFrom);

    if (!isset($certificateData["validTo_time_t"]))
      throw new Exception("validTo_time_t not found in certificate");

    $validTo = (int)$certificateData["validTo_time_t"];

    $this->validTo = gmdate("M j, Y g:i:s A", $validTo);

    $renewAt = intdiv($validFrom + $validTo * 2, 3);

    $this->renewAt = gmdate("M j, Y g:i:s A", $renewAt);

    $this->shouldRenewNow = time() >= $renewAt;

    // *** EXTRACT DOMAIN NAMES ***

    if (!isset($certificateData["extensions"]["subjectAltName"]))
      throw new Exception("SAN extension not found in certificate");

    $sans = explode(", ", $certificateData["extensions"]["subjectAltName"]);

    foreach ($sans as &$san)
    {
      list($type, $value) = explode(":", $san);

      if ($type !== "DNS")
        throw new Exception("Non-DNS SAN found in certificate");

      $san = $value;
    }

    unset($san);

    $this->domainNames = implode("\n", $sans);

    // *** EXTRACT KEY TYPE ***

    $certificateKeyObject = openssl_pkey_get_public($certificateObject);

    if ($certificateKeyObject === false)
      throw new Exception("check certificate key failed");

    $certificateKeyDetails = openssl_pkey_get_details($certificateKeyObject);

    if ($certificateKeyDetails === false)
      throw new Exception("get certificate key details failed");

    switch ($certificateKeyDetails["type"])
    {
      case OPENSSL_KEYTYPE_RSA:

        $this->keyType = "RSA";

        break;

      case OPENSSL_KEYTYPE_EC:

        $this->keyType = "EC";

        break;

      default:

        throw new Exception("unsupported keyType: " . $certificateKeyDetails["type"]);
    }
  }

  public function checkPassword()
  {
    if (!isset($_POST["password"]))
      throw new Exception("password was missing");

    if (!is_string($_POST["password"]))
      throw new Exception("password was not a string");

    if ($_POST["password"] !== $this->password)
      throw new Exception("password was incorrect");
  }

  private function establishAccount()
  {
    // *** ESTABLISH ENVIRONMENT ***

    if (!isset($_POST["environment"]))
      throw new Exception("environment was missing");

    if (!is_string($_POST["environment"]))
      throw new Exception("environment was not a string");

    switch ($_POST["environment"])
    {
      case "production":

        $fileName = "account.key";
        $url = "https://acme-v02.api.letsencrypt.org/directory";

        break;

      case "staging":

        $fileName = "account-staging.key";
        $url = "https://acme-staging-v02.api.letsencrypt.org/directory";

        break;

      default:

        throw new Exception("unknown environment: " . $_POST["environment"]);
    }

    // *** READ ACCOUNT KEY ***

    $this->accountKey = $this->readFile($this->dataDirectory . "/$fileName");

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

    $this->thumbprint = $this->encodeBase64($digest);

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

      $this->writeFile($this->dataDirectory . "/$fileName",
                       $this->accountKey,
                       0644);
    }

    $this->accountUrl = $this->findHeader($response, "location");
  }

  private function dumpResponses()
  {
    $this->writeFile($this->dataDirectory . "/responses.txt",
                     implode("\n\n-----\n\n", array_reverse($this->responses)),
                     0644);
  }

  public function acquireCertificate()
  {
    $this->responses = [];

    try
    {
      $this->establishAccount();

      // *** CREATE NEW ORDER ***

      if (!isset($_POST["domainNames"]))
        throw new Exception("domainNames was missing");

      if (!is_string($_POST["domainNames"]))
        throw new Exception("domainNames was not a string");

      $identifiers = [];

      for ($domainName = strtok($_POST["domainNames"], "\r\n");
           $domainName !== false;
           $domainName = strtok("\r\n"))
        $identifiers[] = [
          "type"  => "dns",
          "value" => $domainName
        ];

      $url = $this->acmeDirectory["newOrder"];

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
          if ($challenge["type"] === "http-01")
          {
            $challengeurls[] = $challenge["url"];
            $challengetokens[] = $challenge["token"];
            continue 2;
          }
        }

        throw new Exception("no http-01 challenge found");
      }

      // *** CREATE HTTP-01 CHALLENGE DIRECTORIES ***

      $this->createDirectory("./.well-known", 0755);
      $this->createDirectory("./.well-known/acme-challenge", 0755);

      try
      {
        // *** WRITE HTTP-01 CHALLENGE FILES ***

        foreach ($challengetokens as $challengetoken)
          $this->writeFile("./.well-known/acme-challenge/$challengetoken",
                           "$challengetoken." . $this->thumbprint,
                           0644);

        // delay for creation of challenge files
        sleep(2);

        // *** CONFIRM CHALLENGES ***

        $payload = (object)[]; // empty object

        foreach ($challengeurls as $url)
          $challenge = $this->sendRequest($url, 200, $payload);

        // delay for processing of challenges
        sleep(6);

        // *** CHECK AUTHORIZATIONS ***

        $payload = ""; // empty

        foreach ($authorizationurls as $url)
        {
          for ($attempt = 1; true; ++$attempt)
          {
            $response = $this->sendRequest($url, 200, $payload);

            $authorization = $this->decodeJSON($response["body"]);

            if ($authorization["status"] !== "pending")
              break;

            if ($attempt == 10)
              throw new Exception("authorization still pending after $attempt attempts");

            // linear backoff
            sleep(2);
          }

          if ($authorization["status"] !== "valid")
            throw new Exception($authorization["challenges"][0]["error"]["type"] . "<br>" . $authorization["challenges"][0]["error"]["detail"]);
        }
      }
      finally
      {
        // *** DELETE HTTP-01 CHALLENGE FILES ***

        foreach ($challengetokens as $challengetoken)
          $this->deleteFile("./.well-known/acme-challenge/$challengetoken");
      }

      // *** GENERATE CERTIFICATE KEY ***

      switch ($_POST["keyType"])
      {
        case "RSA":
  
          $options = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
          ];
  
          break;
  
        case "EC":
  
          $options = [
            "curve_name" => "secp384r1",
            "private_key_type" => OPENSSL_KEYTYPE_EC
          ];
  
          break;
  
        default:
  
          throw new Exception("unknown keyType: " . $_POST["keyType"]);
      }

      $certificateKeyObject = openssl_pkey_new($options);

      if ($certificateKeyObject === false)
        throw new Exception("generate certificate key failed");

      if (!openssl_pkey_export($certificateKeyObject, $certificateKey))
        throw new Exception("export certificate key failed");

      // *** GENERATE CSR ***

      $dn = [
        "commonName" => $identifiers[0]["value"]
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
      foreach ($identifiers as $identifier)
      {
        ++$i;
        $opensslcnf .= "DNS.$i = " . $identifier["value"] . "\n";
      }

      try
      {
        $this->writeFile($this->dataDirectory . "/openssl.cnf",
                         $opensslcnf,
                         0644);

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
        // delay for finalizing order
        sleep(2);

        // *** CHECK ORDER ***

        $url = $orderurl;

        $payload = ""; // empty

        for ($attempt = 1; true; ++$attempt)
        {
          $response = $this->sendRequest($url, 200, $payload);

          $order = $this->decodeJSON($response["body"]);

          if (!(   $order["status"] === "pending"
                || $order["status"] === "processing"
                || $order["status"] === "ready"))
            break;

          if ($attempt == 10)
            throw new Exception("order still pending after $attempt attempts");

          // linear backoff
          sleep(2);
        }

        if ($order["status"] !== "valid")
          throw new Exception("order failed");
      }

      // *** DOWNLOAD CERTIFICATE ***

      $url = $order["certificate"];

      $payload = ""; // empty

      $response = $this->sendRequest($url, 200, $payload);

      $certificate = $response["body"];

      if ($_POST["environment"] == "production")
      {
        // *** WRITE CERTIFICATE AND CERTIFICATE KEY ***

        $this->writeFile($this->dataDirectory . "/certificate.crt",
                         $certificate,
                         0644);

        $this->writeFile($this->dataDirectory . "/certificate.key",
                         $certificateKey,
                         0644);
      }
    }
    finally
    {
      $this->dumpResponses();
    }
  }

  public function installCertificate()
  {
    // *** READ CERTIFICATE ***

    $certificate = $this->readFile($this->dataDirectory . "/certificate.crt");

    if (!isset($certificate))
      throw new Exception("certificate file does not exist");

    // *** EXTRACT CERTIFICATE ***

    $regex = "~^(-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END CERTIFICATE-----)~";
    $outcome = preg_match($regex, $certificate, $matches);

    if ($outcome === false)
      throw new Exception("extract certificate failed");

    if ($outcome === 0)
      throw new Exception("certificate format mismatch");

    $certificate = $matches[1];

    // *** CHECK CERTIFICATE ***

    $certificateObject = openssl_x509_read($certificate);

    if ($certificateObject === false)
      throw new Exception("check certificate failed");

    // *** READ CERTIFICATE KEY ***

    $certificateKey = $this->readFile($this->dataDirectory . "/certificate.key");

    if (!isset($certificateKey))
      throw new Exception("certificate key file does not exist");

    // *** EXTRACT CERTIFICATE KEY ***

    $regex = "~^(-----BEGIN PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END PRIVATE KEY-----)~";
    $outcome = preg_match($regex, $certificateKey, $matches);

    if ($outcome === false)
      throw new Exception("extract certificate key failed");

    if ($outcome === 0)
      throw new Exception("certificate key format mismatch");

    $certificateKey = $matches[1];

    // *** CHECK CERTIFICATE KEY ***

    $certificateKeyObject = openssl_pkey_get_private($certificateKey);

    if ($certificateKeyObject === false)
      throw new Exception("check certificate key failed");

    // *** VERIFY CERTIFICATE AND CERTIFICATE KEY CORRESPOND ***

    if (!openssl_x509_check_private_key($certificateObject, $certificateKeyObject))
      throw new Exception("certificate and certificate key do not correspond");

    // *** EXTRACT DOMAIN NAMES ***

    $certificateData = openssl_x509_parse($certificateObject);

    if ($certificateData === false)
      throw new Exception("parse certificate failed");

    if (!isset($certificateData["extensions"]["subjectAltName"]))
      throw new Exception("No SANs found in certificate");

    $sans = explode(", ", $certificateData["extensions"]["subjectAltName"]);

    foreach ($sans as &$san)
    {
      list($type, $value) = explode(":", $san);

      if ($type !== "DNS")
        throw new Exception("Non-DNS SAN found in certificate");

      $san = $value;
    }

    unset($san);

    // *** INSTALL CERTIFICATE ***

    $domain = $sans[0];
    $domainLength = strlen($sans[0]);

    foreach ($sans as $san)
    {
      $sanLength = strlen($san);

      if ($domainLength <= $sanLength)
        continue;

      $domain = $san;
      $domainLength = $sanLength;
    }

    $cert   = rawurlencode($certificate);
    $key    = rawurlencode($certificateKey);

    unset($output);

    $return = exec("uapi SSL install_ssl domain=$domain cert=$cert key=$key --output=json", $output, $result_code);

    if ($return === false)
      throw new Exception("shell execution pipe could not be established");

    if (!($result_code === 0 && isset($output)))
      throw new Exception("uapi SSL install_ssl failed");

    $output = json_decode(implode("\n", $output));

    if ($output->result->status === 0)
      throw new Exception(empty($output->result->errors) ? "uapi SSL install_ssl error" : implode("<br>", $output->result->errors));

    unset($output);

    $return = exec("uapi SSL toggle_ssl_redirect_for_domains domains=$domain state=1 --output=json", $output, $result_code);

    if ($return === false)
      throw new Exception("shell execution pipe could not be established");

    if (!($result_code === 0 && isset($output)))
      throw new Exception("uapi SSL toggle_ssl_redirect_for_domains failed");

    $output = json_decode(implode("\n", $output));

    if ($output->result->status === 0)
      throw new Exception(empty($output->result->errors) ? "uapi SSL toggle_ssl_redirect_for_domains error" : implode("<br>", $output->result->errors));

    if (!isset($this->autorenew))
    {
      $this->writeFile($this->dataDirectory . "/autorenew.txt",
                       "yes",
                       0644);

      unset($output);

      $return = exec("(crontab -l 2>/dev/null; echo 30 15 \\* \\* \\* curl https://$domain/certsage.php) | crontab -", $output, $result_code);

      if ($return === false)
        throw new Exception("shell execution pipe could not be established");

      if ($result_code !== 0)
        throw new Exception("failed while setting crontab");
    }
  }

  public function updateContact()
  {
    $this->responses = [];

    try
    {
      $this->establishAccount();

      // *** UPDATE CONTACT ***

      if (!isset($_POST["emailAddresses"]))
        throw new Exception("emailAddresses was missing");

      if (!is_string($_POST["emailAddresses"]))
        throw new Exception("emailAddresses was not a string");

      $contact = [];

      for ($emailAddress = strtok($_POST["emailAddresses"], "\r\n");
           $emailAddress !== false;
           $emailAddress = strtok("\r\n"))
        $contact[] = "mailto:$emailAddress";

      $url = $this->accountUrl;

      $payload = [
        "contact" => $contact
      ];

      $response = $this->sendRequest($url, 200, $payload);
    }
    finally
    {
      $this->dumpResponses();
    }
  }
}

// *** MAIN ***

try
{
  $certsage = new CertSage();

  $certsage->initialize();

  if (!isset($_POST["action"]))
  {
    $page = "welcome";

    $certsage->extractCertificateInfo();

    if (   isset($certsage->autorenew)
        && $certsage->autorenew === "yes"
        && $certsage->certificateExists
        && $certsage->shouldRenewNow)
    {
      $_POST["domainNames"] = $certsage->domainNames;
      $_POST["keyType"] = $certsage->keyType;
      $_POST["environment"] = "production";
      $certsage->acquireCertificate();
      $certsage->installCertificate();
    }
  }
  elseif (!is_string($_POST["action"]))
    throw new Exception("action was not a string");
  else
  {
    $page = "success";

    $certsage->checkpassword();

    switch ($_POST["action"])
    {
      case "acquirecertificate":

        $certsage->acquireCertificate();

        break;

      case "installcertificate":

        $certsage->installCertificate();

        break;

      case "updatecontact":

        $certsage->updateContact();

        break;

      default:

        throw new Exception("unknown action: " . $_POST["action"]);
    }
  }
}
catch (Exception $e)
{
  $page = "trouble";

  $error = $e->getMessage();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CertSage</title>
<meta name="description" content="CertSage">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#e1b941">
<meta name="referrer" content="origin">
<style>
*
{
  box-sizing: border-box;
  outline: none;
  margin: 0;
  border: none;
  padding: 0;
  font-weight: normal;
}

html
{
  background: #4169e1;
  font: 100%/1.5 sans-serif;
}

body
{
  position: relative;
  margin: 0 auto;
  max-width: 34rem;
  padding: 1.5rem;
  color: black;
}

a
{
  -webkit-tap-highlight-color: transparent;
}

header, main
{
  border-radius: 1.5rem;
  padding: 1.5rem;
  background: rgba(255,255,255,0.80);
}

main, form, p, footer
{
  margin-top: 1.5rem;
}

header li
{
  display: block;
  text-align: center;
}

header li:first-child
{
  font-size: 2rem;
  line-height: 2.5rem;
  font-family: fantasy;
}

h1
{
  text-align: center;
  font-size: 2rem;
  line-height: 2.5rem;
}

form
{
  text-align: center;
}

h2
{
  font-size: 1.5rem;
  line-height: 2rem;
}

textarea, input
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

input[type="radio"]
{
  margin-top: 0;
  box-shadow: none;
  width: auto;
  border-radius: 0;
  padding: 0;
}

textarea
{
  text-align: left;
}

button
{
  display: inline-block;
  margin: 0.75rem 0.375rem 0;
  box-shadow: 0 0 0.375rem 0 black;
  border: 0.1875rem solid rgba(0,0,0,0.25);
  border-radius: 0.75rem;
  padding: 0.75rem;
  background: lightgray;
  font-size: 1rem;
}

button
{
  -webkit-tap-highlight-color: transparent;
  font: inherit;
  color: inherit;
}

button:active
{
  box-shadow: 0 0 0.375rem 0 black inset;
  border: 0.1875rem solid rgba(0,0,0,0.50);
  font-weight: bold;
}

footer li
{
  display: block;
  margin-top: 1.5rem;
  text-align: center;
  color: rgba(255,255,255,0.80);
}

footer li:first-child
{
  margin-top: 0;
}

footer a
{
  color: inherit;
}

#wait
{
  display: none;
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0,0,0,0.75);
}

#hourglass
{
  position: relative;
  top: calc(50% - 12.5vmin);
  left: calc(50% - 12.5vmin);
  width: 25vmin;
  height: 25vmin;
  font-size: 25vmin;
}
</style>
</head>
<body>
<header>
<ul>
<li>&#x1F9D9;&#x1F3FC;&#x200D;&#x2642;&#xFE0F; CertSage</li>
<li>version <?= $certsage->version ?></li>
<li><a href="https://community.letsencrypt.org/t/certsage-acme-client-version-2-0-0-easy-webpage-interface-optimized-for-cpanel-no-commands-to-type-root-not-required-fully-automated-certificate-renewals/233218" target="_blank">official download and help page</a></li>
<li>support@griffin.software</li>
</ul>
</header>

<main>
<?php
  switch ($page):
    case "welcome":
?>
<h1>Welcome!</h1>

<p>CertSage is an <a href="https://tools.ietf.org/html/rfc8555" target="_blank">ACME</a> client that acquires free <a href="https://en.m.wikipedia.org/wiki/Domain-validated_certificate" target="_blank">DV TLS/SSL certificates</a> from <a href="https://letsencrypt.org/about/" target="_blank">Let's Encrypt</a> by satisfying an <a href="https://letsencrypt.org/docs/challenge-types/#http-01-challenge" target="_blank">HTTP-01 challenge</a> for each <a href="https://en.m.wikipedia.org/wiki/Domain_name" target="_blank">domain name</a> to be covered by a certificate. By using CertSage, you are agreeing to the <a href="https://letsencrypt.org/repository/#let-s-encrypt-subscriber-agreement" target="_blank">Let's Encrypt Subscriber Agreement</a>. Please use the <a href="https://letsencrypt.org/docs/staging-environment/" target="_blank">staging environment</a> for testing to avoid hitting <a href="https://letsencrypt.org/docs/rate-limits/" target="_blank">rate limits</a>.</p>

<form autocomplete="off" method="post" onsubmit="document.getElementById('wait').style.display = 'block';">
<h2>Acquire Certificate</h2>
<?php
      if ($certsage->certificateExists):
?>

<p>
Existing Certificate Details<br>
Issued: <?= $certsage->validFrom ?> UTC<br>
Renew: <?= $certsage->renewAt ?> UTC<br>
Expires: <?= $certsage->validTo ?> UTC<br>
Should Renew Now: <?= $certsage->shouldRenewNow ? "Yes" : "No" ?><br>
</p>
<?php
      endif;
?>

<p>
One domain name per line<br>
No wildcards (*) allowed<br>
<textarea name="domainNames" rows="5"><?= $certsage->domainNames ?></textarea>
</p>

<p>
Key Type<br>
<input name="keyType" value="RSA" type="radio" <?= (!isset($certsage->keyType) || $certsage->keyType === "RSA") ? "checked" : "" ?>> RSA (more compatible)<br>
<input name="keyType" value="EC" type="radio" <?= (isset($certsage->keyType) && $certsage->keyType === "EC") ? "checked" : "" ?>> EC (more efficient)
</p>

<p>
Password<br>
Contents of <?= $certsage->dataDirectory ?>/password.txt<br>
<input name="password" type="password">
</p>

<input name="action" value="acquirecertificate" type="hidden">

<button name="environment" value="staging" type="submit">Acquire Staging Certificate</button>
<button name="environment" value="production" type="submit">Acquire Production Certificate</button>
</form>

<form autocomplete="off" method="post" onsubmit="document.getElementById('wait').style.display = 'block';">
<h2>Install Certificate into cPanel</h2>

<p>
Password<br>
Contents of <?= $certsage->dataDirectory ?>/password.txt<br>
<input name="password" type="password">
</p>

<input name="action" value="installcertificate" type="hidden">

<button name="environment" value="production" type="submit">Install Certificate into cPanel</button>
</form>

<form autocomplete="off" method="post" onsubmit="document.getElementById('wait').style.display = 'block';">
<h2>Receive Let's Encrypt Notifications</h2>

<p>
One email address per line<br>
Leave blank to unsubscribe<br>
<textarea name="emailAddresses" rows="5"></textarea>
</p>

<p>
Password<br>
Contents of <?= $certsage->dataDirectory ?>/password.txt<br>
<input name="password" type="password">
</p>

<input name="action" value="updatecontact" type="hidden">

<button name="environment" value="production" type="submit">Update Contact Information</button>
</form>
<?php
      break;
    case "success":
      switch ($_POST["action"]):
        case "acquirecertificate":
          switch ($_POST["environment"]):
            case "staging":
?>
<h1>Success!</h1>

<p>Your staging certificate was acquired. It was not saved to prevent accidental installation.</p>

<p>Your likely next step is to go back to the beginning to acquire your production certificate.</p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>

<p><a href="">Go back to the beginning</a></p>
<?php
              break;
            case "production":
?>
<h1>Success!</h1>

<p>Your production certificate was acquired. It was saved in <?= $certsage->dataDirectory ?>.</p>

<p>Your likely next step is to go back to the beginning to install your certificate into cPanel.</p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>

<p><a href="">Go back to the beginning</a></p>
<?php
              break;
          endswitch;
          break;
        case "installcertificate":
          switch ($_POST["environment"]):
            case "staging":
?>
This should never happen.
<?php
              break;
            case "production":
?>
<h1>Success!</h1>

<p>Your certificate was installed into cPanel.</p>

<p>Your likely next step is to go back to the beginning to update your contact information.</p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>

<p><a href="">Go back to the beginning</a></p>
<?php
              break;
          endswitch;
          break;
        case "updatecontact":
          switch ($_POST["environment"]):
            case "staging":
?>
This should never happen.
<?php
              break;
            case "production":
?>
<h1>Success!</h1>

<p>Your contact information was updated.</p>

<p>You are likely good to go.</p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>

<p><a href="">Go back to the beginning</a></p>
<?php
              break;
          endswitch;
          break;
      endswitch;
      break;
    case "trouble":
?>
<h1>Trouble...</h1>

<p><?= $error ?></p>

<p>If you need help with resolving this issue, please post a topic in the help category of the <a href="https://community.letsencrypt.org/" target="_blank">Let's Encrypt Community</a>.</p>

<p><a href="">Go back to the beginning</a></p>
<?php
      break;
  endswitch;
?>
</main>

<footer>
<ul>
<li><a href="https://venmo.com/code?user_id=3205885367156736024" target="_blank">Donate to @CertSage via Venmo</a></li>
<li><a href="https://paypal.me/CertSage" target="_blank">Donate to @CertSage via PayPal</a></li>
<li><a href="https://letsencrypt.org/donate/" target="_blank">Donate to Let's Encrypt</a></li>
<li>&copy; 2021-2025 <a href="https://griffin.software" target="_blank">Griffin Software</a></li>
</ul>
</footer>
<div id="wait"><span id="hourglass">&#x23F3;</span></div>
</body>
</html>