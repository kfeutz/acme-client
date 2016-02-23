<?php

namespace Kelunik\AcmeClient\Commands;

use Amp\Dns\Record;
use Exception;
use Kelunik\Acme\AcmeClient;
use Kelunik\Acme\AcmeException;
use Kelunik\Acme\AcmeService;
use Kelunik\Acme\OpenSSLKeyGenerator;
use Kelunik\AcmeClient\Stores\CertificateStore;
use Kelunik\AcmeClient\Stores\ChallengeStore;
use Kelunik\AcmeClient\Stores\KeyStore;
use Kelunik\AcmeClient\Stores\KeyStoreException;
use Kelunik\AcmeClient\Services\Route53ResourceCreator;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;
use League\CLImate\Argument\Manager;
use Psr\Log\LoggerInterface;
use stdClass;
use Throwable;

class Issue implements Command {
    private $logger;

    public function __construct(LoggerInterface $logger) {
        $this->logger = $logger;
    }

    public function execute(Manager $args) {
        return \Amp\resolve($this->doExecute($args));
    }

    private function doExecute(Manager $args) {
        $domains = array_map("trim", explode(",", $args->get("domains")));
        yield \Amp\resolve($this->checkDnsRecords($domains));

        $user = $args->get("user") ?: "www-data";

        $keyStore = new KeyStore(dirname(dirname(__DIR__)) . "/data");

        $keyPair = (yield $keyStore->get("account/key.pem"));
        $configPath = dirname(dirname(__DIR__)) . "/data/account/config.json";
        if (!file_exists($configPath)) {
            throw new AcmeException("Missing account config file. Please register account by running \"bin/acme setup\"");
        }
        $jsonConfig = json_decode(file_get_contents($configPath, false));
        $server = $jsonConfig->server;
        $acme = new AcmeService(new AcmeClient($server, $keyPair), $keyPair);

        $challengeType = $args->get("challenge");

        foreach ($domains as $domain) {
            list($location, $challenges) = (yield $acme->requestChallenges($domain));
            $goodChallenges = $this->findSuitableCombination($challenges, $challengeType);

            if (empty($goodChallenges)) {
                throw new AcmeException("Couldn't find any combination of challenges which this client can solve!");
            }

            $challenge = $challenges->challenges[reset($goodChallenges)];
            $token = $challenge->token;

            if (!preg_match("#^[a-zA-Z0-9-_]+$#", $token)) {
                throw new AcmeException("Protocol Violation: Invalid Token!");
            }

            $this->logger->debug("Generating payload...");
            $payload = $acme->generateHttp01Payload($token);

            $docRoot = rtrim(str_replace("\\", "/", $args->get("path")), "/");
            $challengeStore = new ChallengeStore($docRoot);

            try {
                switch ($challengeType) {
                    case "http-01":
                        $this->logger->info("Providing payload at http://{$domain}/.well-known/acme-challenge/{$token}");
                        $challengeStore->put($token, $payload, $user);

                        yield $acme->selfVerify($domain, $token, $payload);
                        $this->logger->info("Successfully self-verified challenge.");
                        break;
                    case "dns-01":
                        $this->logger->debug("Created Key Auth: " . $payload);
                        $enc = new Base64UrlSafeEncoder;
                        $dns01Payload = $enc->encode(openssl_digest($payload, "sha256", true));
                        $this->logger->info("Generated DNS payload: " . $dns01Payload);

                        $hostedZoneId = $args->get("hostedZoneId");

                        //Create the record set and wait for the batch to complete
                        $route53Creator = new Route53ResourceCreator($hostedZoneId, $dns01Payload, $domain);
                        $batchId = (yield $route53Creator->createRecordSet());
                        $this->logger->info("Created Resource Record Set with batch ID: " . $batchId);
                        $route53Creator->validateChangesDeployed($batchId);
                        $this->logger->info($route53Creator->listResourceRecordSets());

                        $challengeStore->put($token, $payload, $user);
                        break;
                    default:
                        throw new AcmeException("Challenge type must be http-01 or dns-01");
                }
                yield $acme->answerChallenge($challenge->uri, $payload);
                $this->logger->info("Answered challenge... waiting");

                yield $acme->pollForChallenge($location);
                $this->logger->info("Challenge successful. {$domain} is now authorized.");

                yield $challengeStore->delete($token);
            }  catch (Exception $e) {
                // no finally because generators...
                yield $challengeStore->delete($token);
                throw $e;
            } catch (Throwable $e) {
                // no finally because generators...
                yield $challengeStore->delete($token);
                throw $e;
            }
        }

        $path = "certs/" . reset($domains) . "/key.pem";
        $bits = $args->get("bits") ?: 2048;

        try {
            $keyPair = (yield $keyStore->get($path));
        } catch (KeyStoreException $e) {
            $keyPair = (new OpenSSLKeyGenerator)->generate($bits);
            $keyPair = (yield $keyStore->put($path, $keyPair));
        }

        $this->logger->info("Requesting certificate ...");

        $location = (yield $acme->requestCertificate($keyPair, $domains));
        $certificates = (yield $acme->pollForCertificate($location));

        $path = dirname(dirname(__DIR__)) . "/data/certs";
        $certificateStore = new CertificateStore($path);
        yield $certificateStore->put($certificates);

        yield \Amp\File\put($path . "/" . reset($domains) . "/config.json", json_encode([
                "domains" => $domains, "path" => $args->get("path"), "user" => $user, "bits" => $bits,
            ], JSON_PRETTY_PRINT) . "\n");

        $this->logger->info("Successfully issued certificate, see {$path}/" . reset($domains));
    }

    private function checkDnsRecords($domains) {
        $promises = [];

        foreach ($domains as $domain) {
            $promises[$domain] = \Amp\Dns\resolve($domain, [
                "types" => [Record::A],
                "hosts" => false,
            ]);
        }

        list($errors) = (yield \Amp\any($promises));

        if (!empty($errors)) {
            throw new AcmeException("Couldn't resolve the following domains to an IPv4 record: " . implode(array_keys($errors)));
        }

        $this->logger->info("Checked DNS records, all fine.");
    }

    private function findSuitableCombination(stdClass $response, $desiredChallenge) {
        $challenges = isset($response->challenges) ? $response->challenges : [];
        $combinations = isset($response->combinations) ? $response->combinations : [];
        $goodChallenges = [];

        foreach ($challenges as $i => $challenge) {
            if ($challenge->type === "http-01" and $desiredChallenge === "http-01") {
                $goodChallenges[] = $i;
            }
            if ($challenge->type === "dns-01" and $desiredChallenge === "dns-01") {
                $goodChallenges[] = $i;
            }
        }

        foreach ($goodChallenges as $i => $challenge) {
            if (!in_array([$challenge], $combinations)) {
                unset($goodChallenges[$i]);
            }
        }

        return $goodChallenges;
    }

    public static function getDefinition() {
        return [
            "domains" => [
                "prefix" => "d",
                "longPrefix" => "domains",
                "description" => "Comma separated list of domains to request a certificate for.",
                "required" => true,
            ],
            "path" => [
                "prefix" => "p",
                "longPrefix" => "path",
                "description" => "Absolute path to the document root of these domains.",
                "required" => true,
            ],
            "user" => [
                "prefix" => "u",
                "longPrefix" => "user",
                "description" => "User running the web server.",
                "defaultValue" => "www-data",
            ],
            "bits" => [
                "longPrefix" => "bits",
                "description" => "Length of the private key in bit.",
                "defaultValue" => 2048,
                "castTo" => "int",
            ],
            "challenge" => [
                "prefix" => "c",
                "longPrefix" => "challenge",
                "description" => "Which challenge to validate the domain with (http-01 or dns-01).",
                "defaultValue" => "http-01",
            ],
            "hostedZoneId" => [
                "prefix" => "h",
                "longPrefix" => "hosted-zone-id",
                "description" => "Route53 hosted zone for DNS-01 validation.",
            ],
        ];
    }
}