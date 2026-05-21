package policy_test

import data.policy

test_matching_prefixes_allowed if {
	test_input := {"controller_templates": [{"name": "00tenant3-org-config"}]}
	policy.deny with input as test_input
}

test_matching_prefixes_not_allowed if {
	test_input := {"controller_templates": [{"name": "00tenant3-org-config"}]}
	policy.deny with input as test_input
}
