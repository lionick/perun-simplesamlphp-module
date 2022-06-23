<?php

namespace SimpleSAML\Module\perun\Auth\Process;

use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;

/**
 * Attribute filter for generating capabilities from Perun attributes.
 *
 * Example config
 * XX => [
 *     'class' => 'perun:PerunCapabilities',
 *     'capabilityAttribute' => 'eduPersonEntitlement', // defaults to 'eduPersonEntitlement'
 *     'urnNamespace' =>  'urn:mace:egi.eu',
 *     'urnAuthority' => 'aai.egi.eu',
 *     'resAttrMap' => [
 *          'cscaleUserCategory' => 'c-scale:user-category',
 *          'cscaleCompany' => 'c-scale:company',
 *     ]
 * ],
 */
class PerunCapabilities extends ProcessingFilter
{

    /**
     * The attribute that will hold the capability value(s).
     * @var string
     */
    private $capabilityAttribute = 'eduPersonEntitlement';


    /**
     * A string to use as the URN namespace of the generated eduPersonEntitlement 
     * values. 
     * 
     * @var string
     */
    private $urnNamespace = '';


    /**
     * A string to use as the authority of the generated eduPersonEntitlement 
     * values
     * 
     * @var string
     */
    private $urnAuthority = '';


    /**
     * An array of attributes mapped to resources
     * 
     * @var array
     */
    private $resAttrMap = [];


    /**
     * Initialize this filter, parse configuration
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     *
     * @throws SimpleSAML\Error\Exception if the mandatory 'accepted' configuration option is missing.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('capabilityAttribute', $config)) {
            if (!is_string($config['capabilityAttribute'])) {
                Logger::error("[PerunCapabilities] Configuration error: 'capabilityAttribute' not a string literal");
                throw new Exception("PerunCapabilities configuration error: 'capabilityAttribute' not a string literal");
            }
            $this->capabilityAttribute = $config['capabilityAttribute'];
        }

        if (array_key_exists('urnNamespace', $config)) {
            if (!is_string($config['urnNamespace'])) {
                Logger::error("[PerunCapabilities] Configuration error: 'urnNamespace' not a string literal");
                throw new Exception("PerunCapabilities configuration error: 'urnNamespace' not a string literal");
            }
            $this->urnNamespace = $config['urnNamespace'];
        }

        if (array_key_exists('urnAuthority', $config)) {
            if (!is_string($config['urnAuthority'])) {
                Logger::error("[PerunCapabilities] Configuration error: 'urnAuthority' not a string literal");
                throw new Exception("PerunCapabilities configuration error: 'urnAuthority' not a string literal");
            }
            $this->urnAuthority = $config['urnAuthority'];
        }

        if (array_key_exists('resAttrMap', $config)) {
            if (!is_array($config['resAttrMap'])) {
                Logger::error("[PerunCapabilities] Configuration error: 'resAttrMap' not a string literal");
                throw new Exception("PerunCapabilities configuration error: 'resAttrMap' not a string literal");
            }
            $this->resAttrMap = $config['resAttrMap'];
        }
    }


    /**
     *
     * @param array &$state The current SP state
     */
    public function process(&$state)
    {
        assert('is_array($state)');
        Logger::debug("[PerunCapabilities] Processing PerunCapabilities filter");
        foreach ($this->resAttrMap as $perunAttr => $value) {
            // if there is no value in state for perunAttr then do nothing
            if (empty($state['Attributes'][$perunAttr])) {
                continue;
            }
            foreach($state['Attributes'][$perunAttr] as $perunValue) {
                if(empty($perunValue)) {
                    continue;
                }
                $capabilityValue = $this->urnNamespace . ":res:" . $value . ":" . rawurlencode($perunValue) . "#" . $this->urnAuthority;
                if (empty($state['Attributes'][$this->capabilityAttribute])) {
                    $state['Attributes'][$this->capabilityAttribute] = [];
                }
                $state['Attributes'][$this->capabilityAttribute][] = $capabilityValue;
                Logger::debug("[PerunCapabilities] Adding capability " . var_export($capabilityValue, true));
            }
        }
        if (!empty($state['Attributes'][$this->capabilityAttribute])) {
            // Remove duplicates if any
            $state['Attributes'][$this->capabilityAttribute] = array_unique($state['Attributes'][$this->capabilityAttribute]);
        }
    }


}
