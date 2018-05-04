module Cryptorecord
  # Standard Error Class to inherit from
  class Error < StandardError; end
  # Error in argument of a method
  class ArgumentError < Error; end
  # Error with a Digest
  class DigestError < Error; end
  # Error with a Cipher
  class CipherError < Error; end
  # Error with a Mtype(TLSA)
  class MatchTypeError < Error; end
  # Error with a Selector(TLSA)
  class SelectorError < Error; end
  # Any Errors with a Key/Cert
  class KeyError < Error; end
end
