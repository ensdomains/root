# Root

[![Build Status](https://travis-ci.org/ensdomains/root.svg?branch=master)](https://travis-ci.org/ensdomains/root) [![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

This is a proof-of-concept implementation of the new ENS Root layered on top of the previous one as its owner.

This will allow for certain ```onlyOwner``` functions to be disintermediated from the root key holders.

## DNSSEC

The main new functionality is the ability for anyone to register a new `tld`. This can be done by submitting the DNSSEC proof of a specific `tld`. This removes the requirement for the root key holders to enable classic DNS `tld`s.
