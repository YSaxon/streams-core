<?php namespace Anomaly\Streams\Platform\Security;

/**
 * Represents a security policy which need to be enforced when sandbox mode is enabled.
 *
 * @author Yaakov Saxon.
 */
class SecurityPolicyDefaults {
public const INCLUDE_DEFAULTS = '(include_defaults)';
const TAGS = [
    'autoescape',
    'filter',
    'do',
    'flush',
    'for',
    'set',
    'verbatium',
    'if',
    'spaceless',
    'sandbox'
];

const FILTERS =  [
    'abs',
    'batch',
    'capitalize',
    'convert_encoding',
    'date',
    'date_modify',
    'default',
    'escape',
    'first',
    'format',
    'join',
    'json_encode',
    'keys',
    'last',
    'length',
    'lower',
    'merge',
    'nl2br',
    'number_format',
    'raw',
    'replace',
    'reverse',
    'slice',
    'sort',
    'split',
    'striptags',
    'title',
    'trim',
    'upper',
    'url_encode',
    'country_name',
    'currency_name',
    'currency_symbol',
    'language_name',
    'locale_name',
    'timezone_name',
    'format_currency',
    'format_number',
    'format_decimal_number',
    'format_currency_number',
    'format_percent_number',
    'format_scientific_number',
    'format_spellout_number',
    'format_ordinal_number',
    'format_duration_number',
    'format_date',
    'format_datetime',
    'format_time',
];

const FUNCTIONS = [
    'attribute',
    'block',
    'constant',
    'cycle',
    'date',
    'html_classes',
    'max',
    'min',
    'parent',
    'random',
    'range',
    'source',
];

const METHODS = [
    'Twig\Template' => ['*'],
    'Twig\Markup' => ['*'],
    '*' => ['get*', 'has*', 'is*', '__toString', 'toString']
];

const PROPERTIES = [
];


static function addDefaultsToAll(&$allowedTags, &$allowedFilters, &$allowedFunctions, &$allowedMethods, &$allowedProperties)
    {
        $allowedTags = self::addDefaultsToIndexedArray($allowedTags, self::TAGS);

        $allowedFilters = self::addDefaultsToIndexedArray($allowedFilters, self::FILTERS);

        $allowedFunctions = self::addDefaultsToIndexedArray($allowedFunctions, self::FUNCTIONS);

        $allowedMethods = self::addDefaultsToAssociativeArray($allowedMethods, self::METHODS);

        $allowedProperties = self::addDefaultsToAssociativeArray($allowedProperties, self::PROPERTIES);

    }

    static function addDefaultsToIndexedArray(array $array, array $defaults)
    {
        if (in_array(self::INCLUDE_DEFAULTS, $array)) {
            //remove DEFAULTS marker
            $array = array_diff($array, [self::INCLUDE_DEFAULTS]);
            //add defaults
            $array = array_merge($array, $defaults);
            //uniquify
            $array = array_unique($array);
        }
        return $array;
    }

    static function assoc_array_merge($array1, $array2)
    {
        $new_array = [];
        // Merge keys from both arrays
        $all_keys = array_merge(array_keys($array1), array_keys($array2));
        $all_keys = array_unique($all_keys);

        // Iterate through all unique keys
        foreach ($all_keys as $key) {
            $val1 = isset($array1[$key]) ? $array1[$key] : [];
            $val2 = isset($array2[$key]) ? $array2[$key] : [];

            // Convert to array if not already an array
            if (!is_array($val1)) {
                $val1 = [$val1];
            }
            if (!is_array($val2)) {
                $val2 = [$val2];
            }

            // Merge the values and eliminate duplicates
            $combined_vals = array_unique(array_merge($val1, $val2));
            $new_array[$key] = $combined_vals;
        }
        return $new_array;
    }


    static function addDefaultsToAssociativeArray(array $array, array $defaults)
    {
        if (in_array(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $array)) {
            //remove DEFAULTS marker
            $key = array_search(SecurityPolicyDefaults::INCLUDE_DEFAULTS, $array);
            unset($array[$key]);
            //add defaults
            $array = self::assoc_array_merge($array, $defaults);
        }
        return $array;
    }
}