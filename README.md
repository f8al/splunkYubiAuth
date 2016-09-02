# splunkYubiAuth

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
