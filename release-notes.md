## v0.1.4

* Make `CTransaction.stream_deserialize` a @classmethod, as it should be
* set `CT_BITS` to 52 (sync with Elements Core, PR#834)
* Fix sighash calculation when transaction contains asset issuances
* Fix the number of output witnesses after blind. When last outputs
  were not blinded, empty witnesses were not added for them.

Potentially breaking change:

* `Transaction.blind()` method and `blind_transaction()` function now
  accept `is_blind_success_strict` argument, with default value `True`.
  When it is `True`, `BlindFailure` will be returned if the number of
  successfully blinded outputs+issuances is not equal to the number expected
  (as calculated from `output_pubkeys` and `blind_issuance_(asset|token)_keys)`.
  If `is_blind_success_strict` specified as `False`, the behavior will be as
  before, with no checks of number of successful blindings
  This change is unlikely to cause any problems, because in most cases, the
  caller had to check that the number of successfully blinded outputs+issuances
  was as expected. This only makes this more automatic.

## v0.1.3

* Fix `BlindingOrUnblindingResult.ok`: it must be a property, but @property
  decorator was missing. This could result in `unblinding_result.ok` check
  to incorrectly pass in the code that uses the library. This might lead
  to serious bugs, and thus the new version of the library is released with
  the fix.

## v0.1.2

* Fixes to sync with python-bitcointx latest version
* Add type annotations and runtime instance type checks
* Bugfix: `CElementsScript.is_pegout()` could return True incorrectly
  when encountering empty data

## v0.1.1

* Fixes to sync with python-bitcointx latest version

## v0.1.0

Initial release
