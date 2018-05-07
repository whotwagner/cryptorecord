# Cryptorecord

[![GPL Licence](https://badges.frapsoft.com/os/gpl/gpl.png?v=103)](https://github.com/whotwagner/cryptorecord/blob/master/LICENSE.txt)  
[![Build Status](https://travis-ci.org/whotwagner/cryptorecord.svg?branch=master)](https://travis-ci.org/whotwagner/cryptorecord)
[![Inline docs](http://inch-ci.org/github/whotwagner/cryptorecord.svg?branch=master)](http://inch-ci.org/github/whotwagner/cryptorecord)
[![Code Climate](https://codeclimate.com/github/whotwagner/cryptorecord/badges/gpa.svg)](https://codeclimate.com/github/whotwagner/cryptorecord)
[![Test Coverage](https://api.codeclimate.com/v1/badges/dfc3da29d8f7e18f2b0c/test_coverage)](https://codeclimate.com/github/whotwagner/cryptorecord/test_coverage)
[![Gem Version](https://badge.fury.io/rb/cryptorecord.svg)](https://badge.fury.io/rb/cryptorecord)

This gem provides an API and scripts for creating crypto-related dns-records(e.g. DANE).   

At the moment the following records are supported:

  * TLSA
  * SSHFP
  * OPENPGPKEYS

This API does neither create nor provide any public keys/certificates. It just uses existing keys to create the dns-records.


## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cryptorecord'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cryptorecord

## Usage

This gem comes with some example scripts like:

  * openpgpkeysrecord
  * sshfprecord
  * tlsarecord

```bash
Usage: ./openpgpkeysrecord -u <email> -f <gpgkeyfile>
    -h, --help                       This help screen
    -f PGP-PUBLICKEY-FILE,           PGP-Publickey-File
        --publickeyfile
    -u, --uid EMAIL                  email-address

```

```bash
Usage: ./sshfprecord [ options ]
    -h, --help                       This help screen
    -f SSH-HOST-KEY-FILE,            SSH-Hostkey-File
        --hostkeyfile
    -H, --host HOST                  host
    -d, --digest DIGEST              HASH-Algorithm
    -r, --read-local-hostkeys        Read all local Hostkeys.(like ssh-keygen -r)
```

```bash
Usage: ./tlsarecord [ options ]
    -h, --help                       This help screen
    -f, --certfile CERTIFICATE-FILE  Certificatefile
    -H, --host HOST                  host
    -p, --port PORTNUMBER            port
    -P, --protocol PROTOCOL          protocol(tcp,udp,sctp..)
    -s, --selector SELECTOR          Selector for the association. 0 = Full Cert, 1 = SubjectPublicKeyInfo
    -u, --usage USAGE                Usage for the association. 0 = PKIX-CA, 1 = PKIX-EE, 2 = DANE-TA, 3 = DANE-EE
    -t, --mtype MTYPE                The Matching Type of the association. 0 = Exact Match, 1 = SHA-256, 2 = SHA-512
```

### TLSA Example

```ruby
#!/usr/bin/env ruby

require 'cryptorecord'

selector = 0
mtype = 0
usage = 3
port = 443
proto = "tcp"
host = "www.example.com"
tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
tlsa.read_file("/etc/ssl/certs/ssl-cert-snakeoil.pem")
puts tlsa
```

### SSHFP Example 

```ruby
#!/usr/bin/env ruby

require 'cryptorecord'

sshfp = Cryptorecord::Sshfp.new(:digest => 1, :keyfile => '/etc/ssh/ssh_host_rsa_key.pub', :host => 'www.example.com')
puts sshfp
```

### OPENPGPKEYS Example

```ruby
#!/usr/bin/env ruby

require 'cryptorecord'

sshfp = Cryptorecord::Openpgpkeys.new(:uid => "hacky@hacktheplanet.com")
sshfp.read_file("resources/hacky.asc")
puts sshfp

```
## Documentation

[rubydoc.info](https://www.rubydoc.info/gems/cryptorecord/)

## Resources

  * [RFC TLSA](https://tools.ietf.org/html/rfc6698)
  * [RFC DANE/SMTP](https://tools.ietf.org/html/rfc7672)
  * [RFC SSHFP](https://tools.ietf.org/html/rfc4255)
  * [RFC OPENPGPKEYS](https://tools.ietf.org/html/rfc7929)

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. 

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/whotwagner/cryptorecord. This project is intended to be a safe, welcoming space for collaboration.

