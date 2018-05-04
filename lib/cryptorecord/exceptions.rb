module Cryptorecord
  class Error < StandardError; end
  class ArgumentError < Error; end
  class DigestError < Error; end
  class CipherError < Error; end
  class MatchTypeError < Error; end
  class SelectorError < Error; end
  class KeyError < Error; end
end
