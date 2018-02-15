# splunkYubiAuth

still in development, do not use, will not work in current state, may or may not currently contain a monero and dogecoin miner

README
======

* Does not use Splunk's python, uses your system python (or a virtualenv)
* Some OS packages need to be installed
    - openssl-devel
    - python-devel
    - libffi-devel
    - python-pip
* System python needs these modules
    - passlib
    - yubico-client
    - requests
    - requests[security]
    - ldap3
    - more-itertools
    - ConfigParser
