# Ethereum account reader and wallet verification names

## Responsibility and naming

The RPC adapter reads chain ID, an identified Ethereum block and wallet code at
that block. It is not a KERI observer and does not monitor an account continuously.
The policy service checks the wallet proof/configured chain, requests that initial
snapshot, applies account rules, and classifies failed versus retryable results.
Neither owns durable application phases or database transactions.

| Previous name | Replacement | Meaning |
|---|---|---|
| verification/observing.py | verification/accounts.py | Ethereum account RPC adapter |
| AccountObserver | EthAccountReader | Reads a detached initial Ethereum snapshot |
| observe(wallet) | read(wallet) | One finite read, with existing client cleanup |
| observer constructor argument/attribute | account_reader | The concrete borrowed reader dependency |
| EoaVerificationService | WalletVerifier | Wallet proof and initial account policy |
| EoaVerifierDoer | WalletCheckDoer | HIO scheduling of one wallet check |
| EoaVerifierDoer.service | WalletCheckDoer.verifier | The composed WalletVerifier |
| coordinator eoa_verifier argument/attribute | wallet_doer | The borrowed WalletCheckDoer |

Eth is the common Ethereum abbreviation. WalletVerifier identifies the domain
subject without repeating the application name. WalletCheckDoer names the existing HIO request/cue and child-client lifetime
adapter. Keep the separate VerificationService name, but replace its generic
module/class descriptions with the concrete association ACDC, LE/QVI trust-chain,
witnessed issuance and wallet-check contract, including the boundary before local
acceptance and nonce consumption.

## Implementation

1. Finish the independent CLI refactors and qualify their exact coordinated pins.
2. Rename the RPC module/class/method and the policy class; update composition,
   constructor/attribute names and the real RPC test's monkeypatch target together.
   Remove the old module and API names outright; no aliases or deprecated imports.
3. Update maintained architecture/test navigation. Keep historical names in this
   decision map only. Inventory both Oracle and Comply for references before
   deciding whether either needs a source change.
4. Compare executable ASTs after normalizing only the listed symbol/module names
   and removing docstrings. Preserve assertions, matrices, scheduling, RPC calls,
   error classification, snapshot contents, transaction boundaries and topology.
5. Run focused wallet/coordinator tests, build a fresh wheel and check that the new
   module is packaged and the removed module is absent. Run the full installed-wheel
   suite through existing CI, then publish/merge the separate naming PR.

## Boundaries

Preserve accountObservation, observedAt, eoaResult and cue values: these are existing
wire/stored representations, not KERI observer classes. Preserve proof validation
before RPC, matching chain policy, identified-block code reads, failure/retry cues,
per-call timeouts and child-client shutdown on failure or cancellation. No business,
storage or protocol change; no new check script, dependency or framework.

## Implementation evidence

The CLI prerequisite merged as Verifier #42 and Oracle #73: full installed-wheel
suites passed 263 and 87 tests, respectively, including exact-pin paired
qualification. The naming inventory found no affected Python references in Oracle
or Comply. No consumer API or wire change requires a companion there.

All planned names, runtime composition, test imports/patch targets and maintained
architecture references are updated. VerificationService and its module now state
the concrete ACDC, source-chain and wallet checks, KERIpy evidence authority,
retry/error classification, success recheck and pre-acceptance boundary.

A one-off external audit of all 105 Python modules found no unexplained executable
AST changes after applying only the documented rename map and stripping docstrings;
no undocumented definitions remain. Fresh-wheel inventory/help pass, accounts.py
is present, observing.py is absent, and all 263 cases collect outside the checkout.
All 25 installed-wheel wallet/coordinator/service tests pass, including timeout,
cancellation, malformed RPC and proof-before-RPC cases. The existing full
installed-wheel CI suite remains the final merge gate. No new checks are committed.
