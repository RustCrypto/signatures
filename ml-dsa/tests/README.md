ML-DSA Test Vectors
===================

The tests in this directory validate that our ML-RSA implementation successfully
validates the NIST test vectors.  The JSON test vector files are taken from the
[NIST ACVP repository].  Specifically, `key-gen.json`, `sig-gen.json` and
`sig-ver.json` are the "internal projection" files from the [ML-KEM key
generation test directory][keyGen], [signature generation test
directory][sigGen], and [signature verification test directory][sigVer],
respectively.

The current copies of these files were taken from commit [65370b8] of that repo.

The actual tests to be performed are described in the [ACVP documentation].

[NIST ACVP repository]: https://github.com/usnistgov/ACVP-Server/
[keyGen]: https://github.com/usnistgov/ACVP-Server/blob/65370b8/gen-val/json-files/ML-DSA-keyGen-FIPS204
[sigGen]: https://github.com/usnistgov/ACVP-Server/blob/65370b8/gen-val/json-files/ML-DSA-sigGen-FIPS204
[sigVer]: https://github.com/usnistgov/ACVP-Server/blob/65370b8/gen-val/json-files/ML-DSA-sigVer-FIPS204
[65370b8]: https://github.com/usnistgov/ACVP-Server/commit/65370b8
[ACVP documentation]: https://github.com/usnistgov/ACVP/tree/master/src/ml-dsa/sections
