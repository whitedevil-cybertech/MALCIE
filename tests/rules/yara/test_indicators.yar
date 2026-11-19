// ==============================================================================
// MALCIE Dedicated Test YARA Rules (NOT FOR PRODUCTION)
// Author: MALCIE Test Suite
// Purpose: Pipeline verification, synthetic validation, and test harness checks.
// ==============================================================================

rule Test_Indicator_Rule : test validation
{
    meta:
        description = "Test rule for MALCIE static analysis pipeline verification"
        author = "MALCIE Test Suite"
        severity = "low"
        category = "test"
    strings:
        $test_string = "MALCIE_TEST_INDICATOR_SAMPLE" ascii wide
    condition:
        $test_string
}
