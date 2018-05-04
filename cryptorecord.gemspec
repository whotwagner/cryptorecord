# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cryptorecord/version'

Gem::Specification.new do |spec|
  spec.name          = "cryptorecord"
  spec.version       = Cryptorecord::VERSION
  spec.authors       = ["Wolfgang Hotwagner"]
  spec.email         = ["code@feedyourhead.at"]

  spec.summary       = "cryptorecord is a ruby-gem that helps creating crypto-related dns-records like tlsa/sshfp/openpgpkey"
  spec.description   = <<-DESCRIPTION
This gem provides an API and scripts for creating crypto-related dns-records(e.g. DANE).   
At the moment the following records are supported:
  * TLSA
  * SSHFP
  * OPENPGPKEYS

This API does not create nor provide any public keys or certificates. It uses existing keys
to create the dns-records.
DESCRIPTION
  spec.homepage      = "https://github.com/whotwagner/cryptorecord"
  spec.licenses      = ["GPL"]

  # Prevent pushing this gem to RubyGems.org. To allow pushes either set the 'allowed_push_host'
  # to allow pushing to a single host or delete this section to allow pushing to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise "RubyGems 2.0 or newer is required to protect against " \
      "public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features|resources)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
