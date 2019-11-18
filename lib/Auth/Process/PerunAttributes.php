<?php

/**
 * Class sspmod_perun_Auth_Process_PerunAttributes
 *
 * This filter fetches user attributes by its names listed as keys of attrMap config property
 * and set them as Attributes values to keys specified as attrMap values. Old values of Attributes are replaced.
 *
 * It strongly relays on PerunIdentity filter to obtain perun user id. Configure it before this filter properly.
 *
 * if attribute in Perun value is null or is not set at all SSP attribute is set to empty array.
 *
 * @author Ondrej Velisek <ondrejvelisek@gmail.com>
 */
class sspmod_perun_Auth_Process_PerunAttributes extends SimpleSAML_Auth_ProcessingFilter
{
	private $attrMap;
	private $interface;

	/**
	 * @var sspmod_perun_Adapter
	 */
	private $adapter;


	public function __construct($config, $reserved)
	{
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		if (!isset($config['attrMap'])) {
			throw new SimpleSAML_Error_Exception("perun:PerunAttributes: missing mandatory configuration option 'attrMap'.");
		}
		if (!isset($config['interface'])) {
			$config['interface'] = sspmod_perun_Adapter::RPC;
		}

		$this->attrMap = (array) $config['attrMap'];
		$this->interface = (string) $config['interface'];
		$this->adapter = sspmod_perun_Adapter::getInstance($this->interface);
	}


	public function process(&$request)
	{
		assert('is_array($request)');

		if (isset($request['perun']['user'])) {
			$user = $request['perun']['user'];
		} else {
			// throw new SimpleSAML_Error_Exception("perun:PerunAttributes: " .
			// 		"missing mandatory field 'perun.user' in request." .
			// 		"Hint: Have you configured PerunIdentity filter before this filter?"
			// );
			SimpleSAML\Logger::debug("perun:PerunAttributes: 'perun.user' attribute has NOT been found in request. Continuing to next Auth Filter...");
			return;
		}


		$attrs = $this->adapter->getUserAttributes($user, array_keys($this->attrMap));


		foreach ($attrs as $attrName => $attrValue) {

			$sspAttr = $this->attrMap[$attrName];

			// convert $attrValue into array
			if (is_null($attrValue)) {
				$value = array();
			} else if (is_string($attrValue)) {
				$value = array($attrValue);
			} else if ($this->has_string_keys($attrValue)) {
				$value = $attrValue;
			} else if (is_array($attrValue)) {
				$value = $attrValue;
			} else {
				throw new SimpleSAML_Error_Exception("sspmod_perun_Auth_Process_PerunAttributes - Unsupported attribute type. ".
				"Attribute name: $attrName, Supported types: null, string, array, associative array.");
			}

			// convert $sspAttr into array
			if (is_string($sspAttr)) {
				$attrArray = array($sspAttr);
			} else if (is_array($sspAttr)) {
				$attrArray = $sspAttr;
			} else {
				throw new SimpleSAML_Error_Exception("sspmod_perun_Auth_Process_PerunAttributes - Unsupported attribute type. ".
						"Attribute \$attrName, Supported types: string, array.");
			}

			SimpleSAML\Logger::debug("perun:PerunAttributes: perun attribute $attrName was fetched. " .
					"Value " . implode(",", $value) . " is being set to ssp attribute " . implode(",", $attrArray));

			// write $value to all SP attributes
			foreach ($attrArray as $attribute) {
				$request['Attributes'][$attribute] = array_merge($request['Attributes'][$attribute], $value);
			}

		}

	}


	private function has_string_keys($array) {
		if (!is_array($array)) return false;
		return count(array_filter(array_keys($array), 'is_string')) > 0;
	}

}
