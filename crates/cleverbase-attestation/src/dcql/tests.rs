//! Unit tests for the in-core OpenID4VP 1.0 DCQL model + evaluator ([`super`]).
//!
//! Exercises the §6 parse (lenient drop of unsupported/malformed entries), the §"Claims Path Pointer"
//! resolution (JSON-nested + mdoc `[namespace, element]`), §6.3 `values` matching, the §"Selecting
//! Claims" `claim_sets` logic, the §"Selecting Credentials" / §"VP Token Validation" step-3
//! `credential_sets` fold, and the conformance-audit T4.3 role derivation/validation.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    credential_sets_satisfied, evaluate_single, query_satisfied_by, reconcile_role, role_from_meta,
    role_from_type, value_matches, ClaimValue, CredentialMeta, CredentialType, DcqlError, DcqlGate,
    DcqlQuery, PathComponent,
};
use crate::types::{AttributeValue, Format, IssuerRole};

// ---- builders ------------------------------------------------------------------------------------

fn text(value: &str) -> AttributeValue {
    AttributeValue::Text(value.to_owned())
}

fn map(entries: &[(&str, AttributeValue)]) -> AttributeValue {
    AttributeValue::Map(
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

/// An SD-JWT-VC-shaped disclosed attribute set (nested objects + arrays).
fn sd_jwt_disclosed() -> BTreeMap<String, AttributeValue> {
    let mut m = BTreeMap::new();
    m.insert("family_name".to_owned(), text("Doe"));
    m.insert("given_name".to_owned(), text("Ada"));
    m.insert(
        "address".to_owned(),
        map(&[
            ("street_address", text("42 Market Street")),
            ("locality", text("Milliways")),
        ]),
    );
    m.insert(
        "nationalities".to_owned(),
        AttributeValue::Array(vec![text("British"), text("Betelgeusian")]),
    );
    m.insert(
        "degrees".to_owned(),
        AttributeValue::Array(vec![
            map(&[("type", text("BSc"))]),
            map(&[("type", text("MSc"))]),
        ]),
    );
    m.insert("age_over_18".to_owned(), AttributeValue::Boolean(true));
    m.insert("age".to_owned(), AttributeValue::Integer(42));
    m
}

/// An mdoc-shaped disclosed attribute set (namespace-grouped).
fn mdoc_disclosed() -> BTreeMap<String, AttributeValue> {
    let mut m = BTreeMap::new();
    m.insert(
        "org.iso.18013.5.1".to_owned(),
        map(&[
            ("given_name", text("Ada")),
            ("age_over_18", AttributeValue::Boolean(true)),
        ]),
    );
    m
}

// ---- §6 parsing ----------------------------------------------------------------------------------

#[test]
fn parses_a_well_formed_multi_credential_query() {
    let json = r#"{
        "credentials": [
            { "id": "pid", "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claims": [
                  { "id": "fn", "path": ["family_name"] },
                  { "id": "age", "path": ["age_over_18"], "values": [true] }
              ],
              "claim_sets": [["fn", "age"], ["fn"]] },
            { "id": "mdl", "format": "mso_mdoc", "multiple": true,
              "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
              "claims": [ { "path": ["org.iso.18013.5.1", "given_name"] } ] }
        ],
        "credential_sets": [
            { "options": [["pid"], ["mdl"]], "required": true },
            { "options": [["mdl"]] }
        ]
    }"#;
    let query = DcqlQuery::parse(json).expect("well-formed query parses");
    assert_eq!(query.credentials.len(), 2);
    let pid = &query.credentials[0];
    assert_eq!(pid.id, "pid");
    assert_eq!(pid.format, Format::SdJwtVc);
    assert!(!pid.multiple);
    assert_eq!(
        pid.meta,
        CredentialMeta::SdJwtVc {
            vct_values: Some(vec!["urn:eudi:pid:1".to_owned()])
        }
    );
    assert_eq!(pid.claims.len(), 2);
    assert_eq!(
        pid.claims[0].path,
        vec![PathComponent::Key("family_name".to_owned())]
    );
    assert_eq!(pid.claims[1].values, Some(vec![ClaimValue::Boolean(true)]));
    assert_eq!(
        pid.claim_sets,
        vec![
            vec!["fn".to_owned(), "age".to_owned()],
            vec!["fn".to_owned()]
        ]
    );

    let mdl = &query.credentials[1];
    assert_eq!(mdl.format, Format::Mdoc);
    assert!(mdl.multiple);
    assert_eq!(
        mdl.meta,
        CredentialMeta::Mdoc {
            doctype_value: Some("org.iso.18013.5.1.mDL".to_owned())
        }
    );

    assert_eq!(query.credential_sets.len(), 2);
    assert!(query.credential_sets[0].required);
    // `required` omitted ⇒ default true (§6.2).
    assert!(query.credential_sets[1].required);
}

#[test]
fn empty_and_legacy_queries_parse_to_no_credentials() {
    for json in [
        "{}",
        r#"{"credentials":[]}"#,
        r#"{"credentials":[{"id":"pid"}]}"#,
    ] {
        let query = DcqlQuery::parse(json).expect("lenient parse succeeds");
        assert!(
            query.credentials.is_empty(),
            "{json} should yield no evaluable credential queries"
        );
    }
}

#[test]
fn unsupported_format_entries_are_dropped() {
    let json = r#"{"credentials":[
        {"id":"a","format":"jwt_vc_json","meta":{}},
        {"id":"b","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}
    ]}"#;
    let query = DcqlQuery::parse(json).expect("parses");
    assert_eq!(
        query.credentials.len(),
        1,
        "the unsupported jwt_vc_json entry is dropped"
    );
    assert_eq!(query.credentials[0].id, "b");
}

#[test]
fn malformed_sub_entries_are_dropped_leniently() {
    // A non-array / empty `claims` drops the whole query (we never half-enforce a partial claim set).
    for bad_claims in [r#""claims":{}"#, r#""claims":[]"#] {
        let json = format!(
            r#"{{"credentials":[{{"id":"a","format":"dc+sd-jwt","meta":{{}},{bad_claims}}}]}}"#
        );
        assert!(DcqlQuery::parse(&json)
            .expect("parses")
            .credentials
            .is_empty());
    }
    // A claim with a non-array `path`, an invalid path component (a boolean), or a non-scalar `values`
    // element drops the query.
    for bad_claim in [
        r#"{"path":"family_name"}"#,
        r#"{"path":["a",true]}"#,
        r#"{"path":["a"],"values":[{}]}"#,
        r#"{"path":["a"],"values":[null]}"#,
    ] {
        let json = format!(
            r#"{{"credentials":[{{"id":"a","format":"dc+sd-jwt","meta":{{}},"claims":[{bad_claim}]}}]}}"#
        );
        assert!(
            DcqlQuery::parse(&json)
                .expect("parses")
                .credentials
                .is_empty(),
            "malformed claim {bad_claim} drops the query"
        );
    }
    // A Credential Set Query with empty `options` is dropped.
    let json = r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}],"credential_sets":[{"options":[]}]}"#;
    assert!(DcqlQuery::parse(json)
        .expect("parses")
        .credential_sets
        .is_empty());
}

#[test]
fn path_resolution_handles_type_mismatched_components() {
    let disclosed = sd_jwt_disclosed();
    // An index / `null` at the object root cannot apply (the root is an object) → not resolved.
    assert_eq!(sd_jwt_gate("[0]", "", &disclosed), DcqlGate::NotSatisfied);
    // Index / all-elements into a scalar (`family_name` is Text) → not resolved.
    assert_eq!(
        sd_jwt_gate(r#"["family_name",0]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["family_name",null]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
    // A missing key mid-path drains the selection (the loop breaks) → not resolved.
    assert_eq!(
        sd_jwt_gate(r#"["nonexistent","x"]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn meta_kind_mismatch_never_matches() {
    // A defensive arm: the format matches but the verified-type KIND does not match the meta KIND.
    let query = &query_with_sets(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["x"]}}]}"#,
    )
    .credentials[0];
    assert!(!query_satisfied_by(
        query,
        Format::SdJwtVc,
        &CredentialType::DocTypes(vec!["x".to_owned()]),
        &sd_jwt_disclosed()
    ));
}

#[test]
fn legacy_vc_sd_jwt_format_identifier_is_accepted() {
    let json = r#"{"credentials":[{"id":"a","format":"vc+sd-jwt","meta":{"vct_values":["x"]}}]}"#;
    let query = DcqlQuery::parse(json).expect("parses");
    assert_eq!(
        query.credentials.first().map(|c| c.format),
        Some(Format::SdJwtVc)
    );
}

#[test]
fn claim_sets_without_claims_drops_the_query() {
    // §"Selecting Claims": `claim_sets` MUST NOT be present if `claims` is absent.
    let json =
        r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{},"claim_sets":[["x"]]}]}"#;
    assert!(DcqlQuery::parse(json)
        .expect("parses")
        .credentials
        .is_empty());
}

#[test]
fn parse_errors_on_non_json_and_non_object() {
    assert_eq!(DcqlQuery::parse("not json"), Err(DcqlError::Json));
    assert_eq!(DcqlQuery::parse("[]"), Err(DcqlError::NotAnObject));
}

#[test]
fn meta_without_type_constraint_imposes_no_type_restriction() {
    let json = r#"{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{}}]}"#;
    let query = DcqlQuery::parse(json).expect("parses");
    assert_eq!(
        query.credentials.first().map(|c| c.meta.clone()),
        Some(CredentialMeta::SdJwtVc { vct_values: None })
    );
}

// ---- §"Claims Path Pointer" resolution -----------------------------------------------------------

/// Build a one-claim SD-JWT VC query for `path` (with optional `values`) and evaluate it.
fn sd_jwt_gate(path: &str, values: &str, disclosed: &BTreeMap<String, AttributeValue>) -> DcqlGate {
    let json = format!(
        r#"{{"credentials":[{{"id":"c","format":"dc+sd-jwt","meta":{{"vct_values":["urn:eudi:pid:1"]}},"claims":[{{"path":{path}{values}}}]}}]}}"#
    );
    evaluate_single(
        &json,
        Format::SdJwtVc,
        &CredentialType::Vct(Some("urn:eudi:pid:1".to_owned())),
        disclosed,
    )
}

#[test]
fn resolves_top_level_nested_index_and_all_elements_paths() {
    let disclosed = sd_jwt_disclosed();
    assert_eq!(
        sd_jwt_gate(r#"["family_name"]"#, "", &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["address","street_address"]"#, "", &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["nationalities",1]"#, "", &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["degrees",null,"type"]"#, "", &disclosed),
        DcqlGate::Satisfied
    );
    // A missing claim, an out-of-range index, and a key into a scalar do not resolve.
    assert_eq!(
        sd_jwt_gate(r#"["nonexistent"]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["nationalities",9]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["family_name","x"]"#, "", &disclosed),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn value_matching_honors_type_and_value() {
    let disclosed = sd_jwt_disclosed();
    // string match / mismatch
    assert_eq!(
        sd_jwt_gate(r#"["family_name"]"#, r#","values":["Doe"]"#, &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["family_name"]"#, r#","values":["Smith"]"#, &disclosed),
        DcqlGate::NotSatisfied
    );
    // boolean + integer match
    assert_eq!(
        sd_jwt_gate(r#"["age_over_18"]"#, r#","values":[true]"#, &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["age"]"#, r#","values":[42]"#, &disclosed),
        DcqlGate::Satisfied
    );
    assert_eq!(
        sd_jwt_gate(r#"["age"]"#, r#","values":[7]"#, &disclosed),
        DcqlGate::NotSatisfied
    );
    // a type-mismatched expectation (string vs the boolean claim) does not match
    assert_eq!(
        sd_jwt_gate(r#"["age_over_18"]"#, r#","values":["true"]"#, &disclosed),
        DcqlGate::NotSatisfied
    );
}

// ---- §6.1 meta + §"VP Token Validation" step 2.2 (single-presentation gate) ----------------------

#[test]
fn matching_vct_is_satisfied_and_wrong_vct_is_not() {
    let disclosed = sd_jwt_disclosed();
    let json = r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1","https://other/type"]}}]}"#;
    assert_eq!(
        evaluate_single(
            json,
            Format::SdJwtVc,
            &CredentialType::Vct(Some("urn:eudi:pid:1".to_owned())),
            &disclosed
        ),
        DcqlGate::Satisfied
    );
    assert_eq!(
        evaluate_single(
            json,
            Format::SdJwtVc,
            &CredentialType::Vct(Some("urn:wrong:type".to_owned())),
            &disclosed
        ),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn a_presentation_of_a_format_with_no_matching_query_is_not_satisfied() {
    // The query asks only for an mdoc; an SD-JWT VC presentation matches no query → not satisfied.
    let json = r#"{"credentials":[{"id":"c","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}]}"#;
    assert_eq!(
        evaluate_single(
            json,
            Format::SdJwtVc,
            &CredentialType::Vct(Some("x".to_owned())),
            &sd_jwt_disclosed()
        ),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn empty_or_unparseable_query_is_inactive() {
    let disclosed = sd_jwt_disclosed();
    let credential_type = CredentialType::Vct(Some("x".to_owned()));
    for json in [
        "{}",
        r#"{"credentials":[]}"#,
        "not json",
        r#"{"credentials":[{"id":"x"}]}"#,
    ] {
        assert_eq!(
            evaluate_single(json, Format::SdJwtVc, &credential_type, &disclosed),
            DcqlGate::Inactive,
            "{json} imposes no enforceable constraint"
        );
    }
}

#[test]
fn missing_requested_claim_is_not_satisfied() {
    let json = r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["never_disclosed"]}]}]}"#;
    assert_eq!(
        evaluate_single(
            json,
            Format::SdJwtVc,
            &CredentialType::Vct(Some("urn:eudi:pid:1".to_owned())),
            &sd_jwt_disclosed()
        ),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn claim_sets_satisfied_when_one_option_fully_resolves() {
    let disclosed = sd_jwt_disclosed();
    let credential_type = CredentialType::Vct(Some("urn:eudi:pid:1".to_owned()));
    // Option ["fn","missing"] cannot resolve; option ["fn"] can → satisfied via the second option.
    let json = r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
        "claims":[{"id":"fn","path":["family_name"]},{"id":"missing","path":["never"]}],
        "claim_sets":[["fn","missing"],["fn"]]}]}"#;
    assert_eq!(
        evaluate_single(json, Format::SdJwtVc, &credential_type, &disclosed),
        DcqlGate::Satisfied
    );
    // No option fully resolves → not satisfied.
    let json_none = r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
        "claims":[{"id":"missing","path":["never"]}],"claim_sets":[["missing"]]}]}"#;
    assert_eq!(
        evaluate_single(json_none, Format::SdJwtVc, &credential_type, &disclosed),
        DcqlGate::NotSatisfied
    );
}

#[test]
fn mdoc_doctype_match_and_namespaced_claim_path() {
    let disclosed = mdoc_disclosed();
    let json = r#"{"credentials":[{"id":"c","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
        "claims":[{"path":["org.iso.18013.5.1","given_name"]}]}]}"#;
    assert_eq!(
        evaluate_single(
            json,
            Format::Mdoc,
            &CredentialType::DocTypes(vec!["org.iso.18013.5.1.mDL".to_owned()]),
            &disclosed
        ),
        DcqlGate::Satisfied
    );
    // Wrong docType → not satisfied.
    assert_eq!(
        evaluate_single(
            json,
            Format::Mdoc,
            &CredentialType::DocTypes(vec!["org.iso.18013.5.1.other".to_owned()]),
            &disclosed
        ),
        DcqlGate::NotSatisfied
    );
    // A multi-document response with an off-type document fails the all-must-match rule.
    assert_eq!(
        evaluate_single(
            json,
            Format::Mdoc,
            &CredentialType::DocTypes(vec![
                "org.iso.18013.5.1.mDL".to_owned(),
                "org.other".to_owned()
            ]),
            &disclosed,
        ),
        DcqlGate::NotSatisfied
    );
    // An empty docType set never matches a doctype constraint.
    assert_eq!(
        evaluate_single(
            json,
            Format::Mdoc,
            &CredentialType::DocTypes(vec![]),
            &disclosed
        ),
        DcqlGate::NotSatisfied
    );
}

// ---- conformance-audit T4.3 — role derivation/validation -----------------------------------------

#[test]
fn role_is_derived_from_pid_types_only() {
    assert_eq!(
        role_from_type(Format::SdJwtVc, "urn:eudi:pid:1"),
        Some(IssuerRole::Pid)
    );
    assert_eq!(
        role_from_type(Format::SdJwtVc, "eu.europa.ec.eudi.pid.1"),
        Some(IssuerRole::Pid)
    );
    assert_eq!(
        role_from_type(Format::Mdoc, "eu.europa.ec.eudi.pid.1"),
        Some(IssuerRole::Pid)
    );
    // A non-PID type / a PID identifier under the wrong format → no mapping.
    assert_eq!(
        role_from_type(Format::SdJwtVc, "https://credentials.example/identity"),
        None
    );
    assert_eq!(role_from_type(Format::Mdoc, "org.iso.18013.5.1.mDL"), None);
    assert_eq!(role_from_type(Format::Mdoc, "urn:eudi:pid:1"), None);
}

#[test]
fn reconcile_role_derives_validates_and_keeps_unknown() {
    // PID type with a contradicting caller role → reject.
    assert_eq!(
        reconcile_role(IssuerRole::Qeaa, Format::SdJwtVc, "urn:eudi:pid:1"),
        Err(())
    );
    // PID type with the matching role → the derived PID role.
    assert_eq!(
        reconcile_role(IssuerRole::Pid, Format::SdJwtVc, "urn:eudi:pid:1"),
        Ok(IssuerRole::Pid)
    );
    // Unknown type → keep whatever the caller supplied (nothing to validate against).
    assert_eq!(
        reconcile_role(
            IssuerRole::Qeaa,
            Format::SdJwtVc,
            "https://credentials.example/x"
        ),
        Ok(IssuerRole::Qeaa)
    );
}

#[test]
fn role_from_meta_reads_the_expected_type() {
    assert_eq!(
        role_from_meta(&CredentialMeta::SdJwtVc {
            vct_values: Some(vec!["urn:eudi:pid:1".to_owned()])
        }),
        Some(IssuerRole::Pid)
    );
    assert_eq!(
        role_from_meta(&CredentialMeta::Mdoc {
            doctype_value: Some("eu.europa.ec.eudi.pid.1".to_owned())
        }),
        Some(IssuerRole::Pid)
    );
    assert_eq!(
        role_from_meta(&CredentialMeta::SdJwtVc { vct_values: None }),
        None
    );
    assert_eq!(
        role_from_meta(&CredentialMeta::Mdoc {
            doctype_value: Some("org.iso.18013.5.1.mDL".to_owned())
        }),
        None
    );
}

// ---- §"Selecting Credentials" / §"VP Token Validation" step 3 — credential_sets fold -------------

fn query_with_sets(json: &str) -> DcqlQuery {
    DcqlQuery::parse(json).expect("parses")
}

#[test]
fn no_credential_sets_requires_every_credential() {
    let query = query_with_sets(
        r#"{"credentials":[
            {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["x"]}},
            {"id":"b","format":"mso_mdoc","meta":{"doctype_value":"d"}}
        ]}"#,
    );
    let both: BTreeSet<&str> = BTreeSet::from(["a", "b"]);
    let one: BTreeSet<&str> = BTreeSet::from(["a"]);
    assert!(credential_sets_satisfied(&query, &both));
    assert!(
        !credential_sets_satisfied(&query, &one),
        "every credential must be present"
    );
}

#[test]
fn required_set_needs_one_satisfied_option_and_optional_set_does_not_block() {
    let query = query_with_sets(
        r#"{"credentials":[
            {"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["x"]}},
            {"id":"b","format":"mso_mdoc","meta":{"doctype_value":"d"}},
            {"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["y"]}}
        ],
        "credential_sets":[
            {"options":[["a"],["b"]],"required":true},
            {"options":[["c"]],"required":false}
        ]}"#,
    );
    // Required set satisfied via option ["b"]; the optional ["c"] set is absent → still satisfied.
    let b_only: BTreeSet<&str> = BTreeSet::from(["b"]);
    assert!(credential_sets_satisfied(&query, &b_only));
    // Required set NOT satisfied (neither a nor b) → overall fails even though optional c present.
    let c_only: BTreeSet<&str> = BTreeSet::from(["c"]);
    assert!(!credential_sets_satisfied(&query, &c_only));
}

// ---- value matching primitive --------------------------------------------------------------------

#[test]
fn value_matches_only_same_scalar_kind() {
    assert!(value_matches(
        &text("Doe"),
        &[ClaimValue::Text("Doe".to_owned())]
    ));
    assert!(value_matches(
        &AttributeValue::Integer(5),
        &[ClaimValue::Integer(5)]
    ));
    assert!(value_matches(
        &AttributeValue::Boolean(true),
        &[ClaimValue::Boolean(true)]
    ));
    assert!(!value_matches(&text("5"), &[ClaimValue::Integer(5)]));
    assert!(!value_matches(
        &AttributeValue::Null,
        &[ClaimValue::Text(String::new())]
    ));
}

#[test]
fn query_satisfied_by_matches_a_specific_query() {
    let query = &query_with_sets(
        r#"{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["family_name"]}]}]}"#,
    )
    .credentials[0];
    assert!(query_satisfied_by(
        query,
        Format::SdJwtVc,
        &CredentialType::Vct(Some("urn:eudi:pid:1".to_owned())),
        &sd_jwt_disclosed()
    ));
    // Wrong format → no match.
    assert!(!query_satisfied_by(
        query,
        Format::Mdoc,
        &CredentialType::DocTypes(vec!["urn:eudi:pid:1".to_owned()]),
        &mdoc_disclosed()
    ));
}
