<?php

namespace Kelunik\AcmeClient\Services;

use Amp\Dns;
use Amp\CoroutineResult;
use Aws\Route53\Route53Client;
use Guzzle\Service\Resource\Model;
use Namshi\JOSE\Base64\Base64UrlSafeEncoder;

require __DIR__ . "/../../vendor/autoload.php";

//$route53 = new Route53ResourceCreator("Z8GQ8XMIGV7C", "A", "A");
//echo $route53->createSubDomain();
//echo $route53->checkDomainChangeStatus("/change/C2ZW5UGFCL9VFG");

class Route53ResourceCreator {
	private $awsClient;
	private $hostZoneId;
	private $payload;
	private $domainName;

	public function __construct($hostZoneId, $payload, $domainName) {
		$this->awsClient = Route53Client::factory(array(
		    'profile' => 'route53',
		));
		$this->hostZoneId = $hostZoneId;
		$this->payload = $payload;
		$this->domainName = $domainName;
	}

	public function createRecordSet() {
		return \Amp\resolve($this->doCreateRecordSet());
	}

	/**
	 * Creates a new Route53 Resource Record set with the appropriate domain name and payload.
	 * If the Resource Record set already exists, the existing domain name and payload is updated
	 * in that record set.
	 */
	private function doCreateRecordSet() {
		try {
			$result = $this->awsClient->changeResourceRecordSets(array(
			    // HostedZoneId is required
			    'HostedZoneId' => $this->hostZoneId,
			    // ChangeBatch is required
			    'ChangeBatch' => array(
			        'Comment' => 'Test Adding TXT record',
			        // Changes is required
			        'Changes' => array(
			            array(
			                // Action is required
			                'Action' => 'UPSERT',
			                // ResourceRecordSet is required
			                'ResourceRecordSet' => array(
			                    // Name is required
			                    'Name' => '_acme-challenge.' . $this->domainName,
			                    // Type is required
			                    'Type' => 'TXT',
			                    'TTL' => 300,
			                    'ResourceRecords' => array(
			                        array(
			                            // Value is required
			                            'Value' => "\"" . $this->payload . "\"",
			                        ),
			                    ),
			                ),
			            ),
			        ),
			    ),
			));
			yield new CoroutineResult($result['ChangeInfo']['Id']);
			return;
		} catch (Aws\Route53\Exception $e) {
			echo $e->getAwsErrorCode() . "\n";
    		echo $e->getMessage() . "\n";
		}
	}

	public function createSubDomain() {
		try {
			$result = $this->awsClient->changeResourceRecordSets(array(
			    // HostedZoneId is required
			    'HostedZoneId' => $this->hostZoneId,
			    // ChangeBatch is required
			    'ChangeBatch' => array(
			        'Comment' => 'Test Adding subdomain record',
			        // Changes is required
			        'Changes' => array(
			            array(
			                // Action is required
			                'Action' => 'CREATE',
			                // ResourceRecordSet is required
			                'ResourceRecordSet' => array(
			                    // Name is required
			                    'Name' => 'kevin-test2.kf.porticor.net',
			                    // Type is required
			                    'Type' => 'A',
			                    'TTL' => 600,
			                    'ResourceRecords' => array(
			                        array(
			                            // Value is required
			                            'Value' => '52.27.158.59',
			                        ),
			                    ),
			                ),
			            ),
			        ),
			    ),
			));
			return $result['ChangeInfo']['Id'];
		} catch (Aws\Route53\Exception $e) {
			echo $e->getAwsErrorCode() . "\n";
    		echo $e->getMessage() . "\n";
		}
	}

	public function listResourceRecordSets() {
		try {
			$stringResult = "";
			$result = $this->awsClient->listResourceRecordSets(array(
			    // HostedZoneId is required
			    'HostedZoneId' => $this->hostZoneId,
			));
			for ($i = 0; $i < count($result["ResourceRecordSets"]); $i++) {
				$stringResult = $stringResult . " " . $result["ResourceRecordSets"][$i]["Name"] . " " . $result["ResourceRecordSets"][$i]["Type"] 
								. " " . $result["ResourceRecordSets"][$i]["TTL"] . " " . $result["ResourceRecordSets"][$i]["ResourceRecords"][0]["Value"] . "\n";
			}
			return $stringResult;
		} catch (Aws\Route53\Exception $e) {
			echo $e->getAwsErrorCode() . "\n";
    		echo $e->getMessage() . "\n";
		}
	}

	public function checkDomainChangeStatus($batchId) {
		try {
			$result = $this->awsClient->getChange(array(
			    'Id' => $batchId,
			));
			return $result['ChangeInfo']['Status'];
		} catch (Aws\Route53\Exception $e) {
			echo $e->getAwsErrorCode() . "\n";
    		echo $e->getMessage() . "\n";
		}
	}

    public function validateChangesDeployed($batchId) {
        return \Amp\resolve($this->doValidateChangesDeployed($batchId));
    }

	/**
     * Loop until Route53 returns status of INSYNC, meaning changes in Resource Record set
     * have been successfully replicated to all Amazon Route 53 DNS servers.
     *
	 * TODO: wrap in time-out
     */
    public function doValidateChangesDeployed($batchId) {
    	$status = $this->checkDomainChangeStatus($batchId);
        while ($status == "PENDING") {
            sleep(1);
            $status = $this->checkDomainChangeStatus($batchId);
        }
        yield new CoroutineResult($status);
        return;
    }

	public function debug_to_console( $data ) {
        if ( is_array( $data ) )
            $output = "Debug Objects: " . implode( ',', $data);
        else
            $output = "Debug Objects: " . $data;

        echo $output;
    }
}