# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

SAMPLE_POLICY_SCRIPT = f"""
export function apply(profile, phdr) {{
if (profile !== "IETF") {{ return "This policy only accepts IETF did:x509 signed statements"; }}

// Check exact issuer 
if (phdr.cwt.iss !== "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13") {{ return "Invalid issuer"; }}
if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}
if (phdr.cwt.iat === undefined || phdr.cwt.iat < (Math.floor(Date.now() / 1000)) ) {{ return "Invalid iat"; }}

return true;
}}"""

SAMPLE_POLICY_REGO = f"""
package policy

default allow := false

issuer_allowed if {{
    input.phdr.cwt.iss == "did:x509:0:sha256:HnwZ4lezuxq_GVcl_Sk7YWW170qAD0DZBLXilXet0jg::eku:1.3.6.1.4.1.311.10.3.13"
}}

seconds_since_epoch := time.now_ns() / 1000000000

iat_in_the_past if {{
    input.phdr.cwt.iat < seconds_since_epoch
}}

svn_undefined if {{
    not input.phdr.cwt.svn
}}

svn_positive if {{
    input.phdr.cwt.svn >= 0
}}

allow if {{
    issuer_allowed
    iat_in_the_past
    svn_undefined
}}

allow if {{
    issuer_allowed
    iat_in_the_past
    svn_positive
}}
"""

SAMPLE = {
    "js": {"policyScript": SAMPLE_POLICY_SCRIPT},
    "rego": {"policyRego": SAMPLE_POLICY_REGO},
}

INVALID = {
    "js": [
        {"policyScript": ""},
        {"policyScript": "return true"},
        {"policyScript": "function apply() {}"},
        {"policyScript": "function apply() { not valid javascript }"},
    ],
    "rego": [
        {"policyRego": ""},
        {"policyRego": "package policy\n\ninvalid rego"},
    ],
}

RUNTIME_ERROR = {
    "js": {"policyScript": 'export function apply() { throw new Error("Boom"); }'}
}

FAIL_POLICY_REGO = f"""
package policy

default allow := false
"""

FAIL = {
    "js": {
        "policyScript": "export function apply() { return `All entries are refused`; }"
    },
    "rego": {"policyRego": FAIL_POLICY_REGO},
}

PASS_POLICY_REGO = f"""
package policy

default allow := true
"""

PASS = {
    "js": {"policyScript": "export function apply() { return true; }"},
    "rego": {"policyRego": PASS_POLICY_REGO},
}


def svn_policy_script(issuer):
    policy = f"""
export function apply(profile, phdr) {{
    // Check exact issuer 
    if (phdr.cwt.iss !== "{issuer}") {{ return "Invalid issuer"; }}
    if (phdr.cwt.svn === undefined || phdr.cwt.svn < 0) {{ return "Invalid SVN"; }}

    return true;
}}
"""
    return {"policyScript": policy}


def svn_policy_rego(issuer):
    policy = f"""
package policy

default allow := false

issuer_allowed if {{
    input.phdr.cwt.iss == "{issuer}"
}}

svn_positive if {{
    input.phdr.cwt.svn >= 0
    input.phdr.cwt.svn != null
}}

allow if {{
    issuer_allowed
    svn_positive
}}
"""
    return {"policyRego": policy}


SVN = {
    "js": svn_policy_script,
    "rego": svn_policy_rego,
}


def did_x509_policy_script(issuer):
    policy = f"""
export function apply(profile, phdr) {{
    if (profile !== "IETF") {{ return "This policy only accepts IETF did:x509 signed statements"; }}

    // Check exact issuer 
    if (phdr.cwt.iss !== "{issuer}") {{ return "Invalid issuer"; }}

    return true;
}}"""
    return {"policyScript": policy}


def did_x509_policy_rego(issuer):
    policy = f"""
package policy

default allow := false

issuer_allowed if {{
    input.phdr.cwt.iss == "{issuer}"
}}

allow if {{
    issuer_allowed
}}
"""
    return {"policyRego": policy}


DID_X509 = {
    "js": did_x509_policy_script,
    "rego": did_x509_policy_rego,
}
