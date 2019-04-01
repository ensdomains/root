# Root

[![Build Status](https://travis-ci.com/ensdomains/root.svg?branch=master)](https://travis-ci.com/ensdomains/root) [![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

The Root is a contract that will take ownership of the ENS root name in the ENS registry. This allows the keyholders to delegate certain operations to others.

This contract was audited by ConsenSys dilligence; the audit report is available [here](https://github.com/ConsenSys/ens-audit-report-2019-02).

## DNSSEC

The main new functionality is the ability for anyone to register a new `tld`. This can be done by submitting the DNSSEC proof of a specific `tld`. This removes the requirement for the root key holders to enable classic DNS `tld`s.
