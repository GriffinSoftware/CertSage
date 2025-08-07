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

namespace CertSage;
use Exception;

$version = "3.0.0";
$dataDirectory = "../CertSage";

// *** CREATE DIRECTORY ***

function createDirectory($directory)
{
  clearstatcache(true, $directory);

  if (is_dir($directory))
    return;

  if (!mkdir($directory, 0755))
    throw new Exception("could not create directory: $directory");
}

// *** FILE EXISTS ***

function fileExists($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  clearstatcache(true, $filename);

  return is_file($filename);
}

// *** WRITE FILE ***

function writeFile($filename, $data, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  if (file_put_contents($filename, $data, LOCK_EX) === false)
    throw new Exception("could not write file: $filename");

  if (!chmod($filename, 0644))
    throw new Exception("could not set permissions for file: $filename");
}

// *** READ FILE ***

function readFile($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  $data = file_get_contents($filename);

  if ($data === false)
    throw new Exception("could not read file: $filename");

  return $data;
}

// *** DELETE FILE ***

function deleteFile($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  if (!unlink($filename))
    throw new Exception("could not delete file: $filename");
}

// *** ENCODE JSON ***

function encodeJSON($value)
{
  $json = json_encode($value, JSON_UNESCAPED_SLASHES);

  if (json_last_error() != JSON_ERROR_NONE)
    throw new Exception("encode JSON failed");

  return $json;
}

// *** DECODE JSON ***

function decodeJSON($json)
{
  $value = json_decode($json, true);

  if (json_last_error() != JSON_ERROR_NONE)
    throw new Exception("decode JSON failed");

  return $value;
}

// *** ENCODE BASE64 ***

function encodeBase64($string)
{
  return strtr(rtrim(base64_encode($string), "="), "+/", "-_");
}

// *** FIND HEADER ***

function findHeader($response, $target, $required = true)
{
  $regex = "~^$target: ([^\r\n]+)[\r\n]*~i";
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

// *** SEND REQUEST ***

function sendRequest($url, $expectedResponseCode, $payload = null, $jwk = null)
{
  global $version;
  global $account;
  static $nonce = null;

  $headers = [];
  $headerSize = 0;

  $ch = curl_init($url);

  if ($ch === false)
    throw new Exception("cURL initialization failed");

  if (!curl_setopt($ch, CURLOPT_USERAGENT, "CertSage/" . $version . " (support@griffin.software)"))
    throw new Exception("cURL set user agent option failed");

  if (!curl_setopt($ch, CURLOPT_RETURNTRANSFER, true))
    throw new Exception("cURL set return transfer option failed");

  if (isset($payload))
  {
    if (!isset($nonce))
    {
      $response = sendRequest($account["acmeDirectory"]["newNonce"], 204);

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
      $protected["kid"] = $account["URL"];

    $protected = encodeBase64(encodeJSON($protected));

    if ($payload !== "")
      $payload = encodeBase64(encodeJSON($payload));

    if (openssl_sign("$protected.$payload", $signature, $account["key"], "sha256WithRSAEncryption") === false)
      throw new Exception("openssl sign failed");

    $signature = encodeBase64($signature);

    $josejson = encodeJSON([
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

  $account["responses"][] = $body;

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
    if (findHeader($response, "content-type", false) === "application/problem+json")
    {
      $problem = decodeJSON($response["body"]);

      if (isset($problem["type"], $problem["detail"]))
        throw new Exception($problem["type"] . "<br>" . $problem["detail"]);
    }

    throw new Exception("unexpected response code: $responseCode vs $expectedResponseCode");
  }

  $nonce = findHeader($response, "replay-nonce", false);

  return $response;
}

// *** ACQUIRE CERTIFICATE ***

function acquireCertificate($environment)
{
  global $dataDirectory;
  global $account;

  $account = [];
  $account["responses"] = [];

  try
  {
    // *** ESTABLISH ENVIRONMENT ***

    switch ($environment)
    {
      case "production":

        $filename = "account.key";
        $url = "https://acme-v02.api.letsencrypt.org/directory";
        break;

      case "staging":

        $filename = "account-staging.key";
        $url = "https://acme-staging-v02.api.letsencrypt.org/directory";
        break;
    }

    $accountKeyExists = fileExists($filename);

    if ($accountKeyExists)
    {
      // *** READ ACCOUNT KEY ***

      $account["key"] = readFile($filename);

      // *** CHECK ACCOUNT KEY ***

      $accountKeyObject = openssl_pkey_get_private($account["key"]);

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

      if (!openssl_pkey_export($accountKeyObject, $account["key"]))
        throw new Exception("export account key failed");
    }

    // *** GET ACCOUNT KEY DETAILS ***

    $accountKeyDetails = openssl_pkey_get_details($accountKeyObject);

    if ($accountKeyDetails === false)
      throw new Exception("get account key details failed");

    // *** CONSTRUCT JWK ***

    $jwk = [
      "e" => encodeBase64($accountKeyDetails["rsa"]["e"]), // public exponent
      "kty" => "RSA",
      "n" => encodeBase64($accountKeyDetails["rsa"]["n"])  // modulus
    ];

    // *** CALCULATE THUMBPRINT ***

    $digest = openssl_digest(encodeJSON($jwk), "sha256", true);

    if ($digest === false)
      throw new Exception("digest JWK failed");

    $thumbprint = encodeBase64($digest);

    // *** GET ACME DIRECTORY ***

    $response = sendRequest($url, 200);

    $account["acmeDirectory"] = decodeJSON($response["body"]);

    if ($accountKeyExists)
    {
      // *** LOOKUP ACCOUNT ***

      $url = $account["acmeDirectory"]["newAccount"];

      $payload = [
        "onlyReturnExisting" => true
      ];

      $response = sendRequest($url, 200, $payload, $jwk);
    }
    else
    {
      // *** REGISTER ACCOUNT ***

      $url = $account["acmeDirectory"]["newAccount"];

      $payload = [
        "termsOfServiceAgreed" => true
      ];

      $response = sendRequest($url, 201, $payload, $jwk);

      // *** WRITE ACCOUNT KEY ***

      writeFile($filename, $account["key"]);
    }

    $account["URL"] = findHeader($response, "location");

    // *** CREATE NEW ORDER ***

    if (!isset($_POST["identifiers"]))
      throw new Exception("identifiers was missing");

    if (!is_string($_POST["identifiers"]))
      throw new Exception("identifiers was not a string");

    $identifiers = [];

    for ($identifier = strtok($_POST["identifiers"], "\r\n");
         $identifier !== false;
         $identifier = strtok("\r\n"))
      $identifiers[] = [
        "type"  => "dns",
        "value" => $identifier
      ];

    $url = $account["acmeDirectory"]["newOrder"];

    $payload = [
      "identifiers" => $identifiers
    ];

    $response = sendRequest($url, 201, $payload);

    $orderurl = findHeader($response, "location");
    $order = decodeJSON($response["body"]);

    // *** GET CHALLENGES ***

    $authorizationurls = [];
    $challengeurls = [];
    $challengetokens = [];

    $payload = ""; // empty

    foreach ($order["authorizations"] as $url)
    {
      $response = sendRequest($url, 200, $payload);

      $authorization = decodeJSON($response["body"]);

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

    createDirectory("./.well-known");
    createDirectory("./.well-known/acme-challenge");

    try
    {
      // *** WRITE HTTP-01 CHALLENGE FILES ***

      foreach ($challengetokens as $challengetoken)
        writeFile("./.well-known/acme-challenge/$challengetoken",
                  "$challengetoken.$thumbprint",
                  false);

      // delay for creation of challenge files
      sleep(2);

      // *** CONFIRM CHALLENGES ***

      $payload = (object)[]; // empty object

      foreach ($challengeurls as $url)
        $challenge = sendRequest($url, 200, $payload);

      // delay for processing of challenges
      sleep(6);

      // *** CHECK AUTHORIZATIONS ***

      $payload = ""; // empty

      foreach ($authorizationurls as $url)
      {
        for ($attempt = 1; true; ++$attempt)
        {
          $response = sendRequest($url, 200, $payload);

          $authorization = decodeJSON($response["body"]);

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
        deleteFile("./.well-known/acme-challenge/$challengetoken", false);
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
      "config" => "$dataDirectory/openssl.cnf"
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
      writeFile("openssl.cnf", $opensslcnf);

      $csrObject = openssl_csr_new($dn, $certificateKey, $options);

      if ($csrObject === false)
        throw new Exception("generate csr failed");
    }
    finally
    {
      deleteFile("openssl.cnf");
    }

    if (!openssl_csr_export($csrObject, $csr))
      throw new Exception("export csr failed");

    // *** FINALIZE ORDER ***

    $url = $order["finalize"];

    $outcome = preg_match("~^-----BEGIN CERTIFICATE REQUEST-----([^\-]+)-----END CERTIFICATE REQUEST-----~",
                          str_replace("\n", "", $csr),
                          $matches);

    if ($outcome === false)
      throw new Exception("extract csr failed");

    if ($outcome === 0)
      throw new Exception("csr format mismatch");

    $payload = [
      "csr" => strtr(rtrim($matches[1], "="), "+/", "-_")
    ];

    $response = sendRequest($url, 200, $payload);

    $order = decodeJSON($response["body"]);

    if ($order["status"] !== "valid")
    {
      // delay for finalizing order
      sleep(2);

      // *** CHECK ORDER ***

      $url = $orderurl;

      $payload = ""; // empty

      for ($attempt = 1; true; ++$attempt)
      {
        $response = sendRequest($url, 200, $payload);

        $order = decodeJSON($response["body"]);

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

    $response = sendRequest($url, 200, $payload);

    $certificate = $response["body"];

    if ($environment === "production")
    {
      // *** WRITE CERTIFICATE AND CERTIFICATE KEY ***

      writeFile("certificate.crt", $certificate);
      writeFile("certificate.key", $certificateKey);
    }
  }
  finally
  {
    writeFile("responses.txt",
              implode("\n\n-----\n\n", array_reverse($account["responses"])));
  }
}

// *** IMPORT CERTIFICATE ***

function importCertificate()
{
  global $certificate;

  $certificate = [];
  $certificate["valid"] = false;

  // *** EXTRACT CERTIFICATE AND KEY ***

  $certificateMissing    = !fileExists("certificate.crt");
  $certificateKeyMissing = !fileExists("certificate.key");

  if ($certificateMissing && $certificateKeyMissing)
    return;

  if ($certificateMissing)
    throw new Exception("certificate.crt file missing");

  if ($certificateKeyMissing)
    throw new Exception("certificate.key file missing");

  $outcome = preg_match("~^(-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END CERTIFICATE-----)~",
                        readFile("certificate.crt"),
                        $matches);

  if ($outcome === false)
    throw new Exception("extract certificate failed");

  if ($outcome === 0)
    throw new Exception("certificate format mismatch");

  $certificate["certificate"] = $matches[1];

  $outcome = preg_match("~^(-----BEGIN PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END PRIVATE KEY-----)~",
                        readFile("certificate.key"),
                        $matches);

  if ($outcome === false)
    throw new Exception("extract certificate key failed");

  if ($outcome === 0)
    throw new Exception("certificate key format mismatch");

  $certificate["key"] = $matches[1];

  // *** CHECK CERTIFICATE AND KEY ***

  $certificateObject = openssl_x509_read($certificate["certificate"]);

  if ($certificateObject === false)
    throw new Exception("check certificate failed");

  $certificateKeyObject = openssl_pkey_get_private($certificate["key"]);

  if ($certificateKeyObject === false)
    throw new Exception("check certificate key failed");

  if (!openssl_x509_check_private_key($certificateObject, $certificateKeyObject))
    throw new Exception("certificate and certificate key do not correspond");

  // *** PARSE CERTIFICATE ***

  $certificateData = openssl_x509_parse($certificateObject);

  if ($certificateData === false)
    throw new Exception("parse certificate failed");

  // *** EXTRACT TIMES ***

  $time = time();
  $certificate["validFrom"] = (int)$certificateData["validFrom_time_t"];
  $certificate["validTo"]   = (int)$certificateData["validTo_time_t"];
  $certificate["renewAt"]   = intdiv($certificate["validFrom"] + $certificate["validTo"] * 2, 3);
  $certificate["renewNow"]  = $time >= $certificate["renewAt"];
  $certificate["expired"]   = $time >= $certificate["validTo"];

  // *** EXTRACT DOMAIN NAMES ***

  $sans = explode(", ", $certificateData["extensions"]["subjectAltName"]);

  foreach ($sans as &$san)
  {
    list($type, $value) = explode(":", $san);

    if ($type !== "DNS")
      throw new Exception("Non-DNS SAN found in certificate");

    $san = $value;
  }

  unset($san);

  $certificate["identifiers"] = $sans;

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

      $certificate["keyType"] = "RSA";
      break;

    case OPENSSL_KEYTYPE_EC:

      $certificate["keyType"] = "EC";
      break;

    default:

      throw new Exception("unsupported keyType: " . $certificateKeyDetails["type"]);
  }

  $certificate["valid"] = true;
}

// *** INSTALL CERTIFICATE ***

function installCertificate()
{
  global $certificate;

  // *** INSTALL CERTIFICATE INTO CPANEL ***

  $domain = $certificate["identifiers"][0];
  $domainLength = strlen($certificate["identifiers"][0]);

  foreach ($certificate["identifiers"] as $san)
  {
    $sanLength = strlen($san);

    if ($sanLength >= $domainLength)
      continue;

    $domain = $san;
    $domainLength = $sanLength;
  }

  $cert = rawurlencode($certificate["certificate"]);
  $key  = rawurlencode($certificate["key"]);

  unset($output);

  $return = exec("uapi SSL install_ssl domain=$domain cert=$cert key=$key --output=json", $output, $result_code);

  if ($return === false)
    throw new Exception("shell execution pipe could not be established");

  if ($result_code !== 0)
    throw new Exception("uapi SSL install_ssl failed");

  $output = json_decode(implode("\n", $output));

  if ($output->result->status === 0)
    throw new Exception(empty($output->result->errors) ? "uapi SSL install_ssl error" : implode("<br>", $output->result->errors));

  // *** ENABLE HTTP->HTTPS REDIRECT ***

  unset($output);

  $return = exec("uapi SSL toggle_ssl_redirect_for_domains domains=$domain state=1 --output=json", $output, $result_code);

  if ($return === false)
    throw new Exception("shell execution pipe could not be established");

  if ($result_code !== 0)
    throw new Exception("uapi SSL toggle_ssl_redirect_for_domains failed");

  $output = json_decode(implode("\n", $output));

  if ($output->result->status === 0)
    throw new Exception(empty($output->result->errors) ? "uapi SSL toggle_ssl_redirect_for_domains error" : implode("<br>", $output->result->errors));

  // *** SETUP AUTORENEWAL ***

  if (!fileExists("autorenew.txt"))
  {
    unset($output);

    $return = exec("(crontab -l 2>/dev/null; echo 30 15 \\* \\* \\* curl https://$domain/certsage.php) | crontab -", $output, $result_code);

    if ($return === false)
      throw new Exception("shell execution pipe could not be established");

    if ($result_code !== 0)
      throw new Exception("failed while setting crontab");

    writeFile("autorenew.txt", "yes");
  }
}

// *** MAIN ***

try
{
  if (isset($_POST["action"]))
  {
    $page = "success";

    // *** INITIALIZE ***

    importCertificate();

    // *** CHECK PASSWORD ***

    if (!isset($_POST["password"]))
      throw new Exception("password was missing");

    if (!is_string($_POST["password"]))
      throw new Exception("password was not a string");

    if (!fileExists("password.txt"))
      throw new Exception("password.txt file missing");

    if ($_POST["password"] !== readFile("password.txt"))
      throw new Exception("password was incorrect");

    // *** PROCESS ACTION ***

    if (!is_string($_POST["action"]))
      throw new Exception("action was not a string");

    switch ($_POST["action"])
    {
      case "acquireandinstall":

        acquireCertificate("production");
        importCertificate();
        installCertificate();
        $message = "Certificate acquired and installed into cPanel.";
        break;

      case "acquire":

        acquireCertificate("production");
        importCertificate();
        $message = "Certificate acquired.";
        break;

      case "install":

        installCertificate();
        $message = "Certificate installed into cPanel.";
        break;

      case "test":

        acquireCertificate("staging");
        $message = "Test passed.";
        break;

      default:

        throw new Exception("unknown action: " . $_POST["action"]);
    }
  }
  else
  {
    $page = "welcome";

    // *** INITIALIZE ***

    createDirectory($dataDirectory);

    if (!fileExists("password.txt"))
      writeFile("password.txt", encodeBase64(openssl_random_pseudo_bytes(15)));

    importCertificate();

    // *** PROCESS RENEWAL ***

    if (   $certificate["valid"]
        && $certificate["renewNow"]
        && fileExists("autorenew.txt")
        && readFile("autorenew.txt") === "yes")
    {
      $_POST["identifiers"] = implode("\n", $certificate["identifiers"]);
      $_POST["keyType"]     = $certificate["keyType"];
      acquireCertificate("production");
      importCertificate();
      installCertificate();
    }
  }
}
catch (Exception $e)
{
  $page = "trouble";
  $message = $e->getMessage();
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

main, p, footer
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
<li>version <?= $version ?></li>
<li>support@griffin.software</li>
</ul>
</header>

<main>
<?php
switch ($page):
  case "welcome":
?>
<h1>Welcome!</h1>

<p>CertSage is an <a href="https://tools.ietf.org/html/rfc8555" target="_blank">ACME</a> client that acquires free <a href="https://en.m.wikipedia.org/wiki/Domain-validated_certificate" target="_blank">DV TLS/SSL certificates</a> from <a href="https://letsencrypt.org/about/" target="_blank">Let's Encrypt</a> by satisfying an <a href="https://letsencrypt.org/docs/challenge-types/#http-01-challenge" target="_blank">HTTP-01 challenge</a> for each <a href="https://en.m.wikipedia.org/wiki/Domain_name" target="_blank">domain name</a> to be covered by a certificate.</p>

<p>By using CertSage, you are agreeing to the <a href="https://letsencrypt.org/repository/#let-s-encrypt-subscriber-agreement" target="_blank">Let's Encrypt Subscriber Agreement</a>.</p>
<?php
    break;
  case "success":
?>
<h1>Success!</h1>

<p><?= $message ?></p>

<p>If you like free and easy certificates, please consider donating to CertSage and Let's Encrypt using the links at the bottom of this page.</p>
<?php
    break;
  case "trouble":
?>
<h1>Trouble...</h1>

<p><?= $message ?></p>

<p>If you need help resolving this issue, please post a help topic in the <a href="https://community.letsencrypt.org/" target="_blank">Let's Encrypt Community</a>.</p>
<?php
    break;
endswitch;
?>

<form autocomplete="off" method="post" onsubmit="document.getElementById('wait').style.display = 'block';">
<?php
if ($certificate["valid"]):
?>
<p>
Existing Certificate Details<br>
<div style="text-align: left; color: green">
Issued: <?= gmdate("M j, Y g:i:s A", $certificate["validFrom"]); ?> UTC
</div>
<div style="text-align: left; color: <?= $certificate["renewNow"] ? "yellow" : "green" ?>">
Renew: <?= gmdate("M j, Y g:i:s A", $certificate["renewAt"]); ?> UTC
</div>
<div style="text-align: left; color: <?= $certificate["expired"] ? "red" : "green" ?>">
Expiry: <?= gmdate("M j, Y g:i:s A", $certificate["validTo"]); ?> UTC
</div>
</p>
<?php
endif;
?>

<p>
Domain and Subdomain Names<br>
One per line; No wildcards (*)<br>
<textarea name="identifiers" rows="5"><?= $certificate["valid"] ? implode("\n", $certificate["identifiers"]) : "" ?></textarea>
</p>

<p>
Key Type<br>
<input name="keyType" value="RSA" type="radio" <?= (!$certificate["valid"] || $certificate["keyType"] === "RSA") ? "checked" : "" ?>> RSA (more compatible)<br>
<input name="keyType" value="EC"  type="radio" <?= ( $certificate["valid"] && $certificate["keyType"] === "EC" ) ? "checked" : "" ?>> EC  (more efficient)
</p>

<p>
Password<br>
<input name="password" type="password">
</p>

<button name="action" value="acquireandinstall" type="submit">Acquire Certificate and<br>Install into cPanel</button><br>
<button name="action" value="acquire" type="submit">Acquire Certificate</button><br>
<button name="action" value="install" type="submit">Install into cPanel</button><br>
<button name="action" value="test" type="submit">Test</button>
</form>
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