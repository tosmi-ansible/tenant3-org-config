package policy

deny contains msg if {
	print("input is: ", input)

	some jt in input.controller_templates

	# Extract values from input
	# jt_name := object.get(input, ["job_template", "name"], "")
	jt_name := jt.name

	# Construct the expected prefix
	# expected_prefix := concat("-", [org_name])

	# Check if job template name starts with expected prefix
	# not startswith(jt_name, expected_prefix)

	not regex.match(`^\d{32}-.+`, jt_name)

	msg := "Job template does not comply with naming convention"
}

# result := {
# 	"allowed": false,
# 	"violations": [sprintf("Job template naming for '%v' does not follow <id>-<org>-<rest>", [jt_name])],
# }
