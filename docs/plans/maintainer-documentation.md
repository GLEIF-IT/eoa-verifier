# Maintainer documentation pass

Scope: every tracked Python module, class, method, function, test, fixture/helper and constant in eoa-verifier, including nested test doubles and integration/protocol tooling. Preserve behavior and current topology. Documentation lives beside the implementation; guides explain navigation and operating contracts.

1. Inventory all definitions and constants, then manually review existing documentation quality. Qualified baseline: 105 modules, 83 classes, 483 functions/methods and 21 uppercase assignments; 76 missing definition docstrings. The subprocess program embedded in WORKER has one additional module, one class and four methods; document and compare that program separately.
2. Review production modules by feature. Explain ownership/lifetime, inputs and representations, outcomes, side effects, durable/atomic boundaries, exceptions, generator scheduling and relevant trust/validation assumptions. Document record fields, units and invariants, and the purpose/provenance of constants. Avoid boilerplate restating names.
3. Review integration/protocol tooling. Explain process and store ownership, exact source/artifact selection, startup/readiness/OOBI flow, cleanup and retained diagnostic artifacts. Document CLI entry points and callbacks.
4. Review every test and shared fixture/helper, including nested doubles and fault injectors. State the protected behavior, fixture resource scope/topology, simulated boundary and observable outcomes. Preserve every assertion, parameter matrix and test name.
5. Update testing/maintainer navigation and any conflicting operational explanations. Add no architecture/docs-check script, generic framework, compatibility API, or unrelated cleanup.
6. Verify zero undocumented definitions, review constants and record attributes manually, and prove documentation-stripped AST equality against the qualified baseline. Build/install the wheel, collect the unchanged test matrix and smoke CLI help. Use existing CI; no new documentation enforcement gate. Publish a separate cohesive PR and merge once checks pass under standing authorization.

## LMDB schema comments

Document every locally defined LMDBer subclass in Verifier and Oracle: VerifierBaser,
VerifierReger (through KERIpy Reger), and OracleBaser. Each local subdatabase binding
gets a concise key -> value comment and its lifecycle/purpose. Include fixture-owned
receiver tables borrowed from a KERIpy Baser; inherited upstream bindings stay
documented upstream. Directory constants and typed record fields explain ownership,
units and representation. The Oracle companion changes documentation only.

## Review evidence

The pass fills all 76 previously undocumented definitions and the embedded worker's
module/class/four methods. All 105 tracked modules, 83 classes and 483 functions
have docstrings; including the embedded program gives 106/84/487. All 21 uppercase
assignment occurrences and application directory constants have adjacent explanations.
Existing useful contracts remain; expanded records and persistence class contracts
explain field meaning, detached reads and atomic-write preconditions.

A one-off audit outside the repository found zero executable AST differences in
either component after stripping docstrings (and separately parsing WORKER). No
JSON schema/vector, test assertion, parameter matrix or integration topology changed.
Fresh wheels contained the complete Python/schema inventory, CLI help succeeded,
and collection remained 258 Verifier / 83 Oracle cases. Focused installed-wheel
checks passed 38 Verifier persistence/revocation cases, including real subprocess
races/death, and 5 Oracle persistence cases. Existing full installed-wheel CI remains
the merge gate; the Oracle job includes maintained paired qualification. No new
check script or CI gate was added.
