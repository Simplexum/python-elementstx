## v0.1.4.dev0

* set `CT_BITS` to 52 (sync with Elements Core, PR#834)
* Fix sighash calculation when transaction contains asset issuances

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
