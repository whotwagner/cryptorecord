#--
# Copyright (C) 2018 Wolfgang Hotwagner <code@feedyourhead.at>
#
# This file is part of the cryptorecord gem
#
# This cryptorecord gem is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This cryptorecord gem is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this cryptorecord gem; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301  USA
#++

# This module provides the api for cryptorecords
module Cryptorecord
  require 'openssl'
  require 'base64'
  # Cryptorecord::Sshfp-class generates
  # sshfp-dns-records. The ssh-host-keys are
  # read from files
  # @!attribute [r] cipher
  #   @return [Integer]the cipher. ssh-rsa = 1, ssh-dss = 2,
  #     ecdsa = 3 and ed25519 = 4
  # @!attribute [r] digest
  #   @return [Integer] sha1 = 1, sha256 = 2
  # @!attribute [r]  key
  #   @return [String] the ssh-host-key, without the type and comment
  # @!attribute [r] rectype
  #   @return [String] "SSHFP"
  # @!attribute host
  #   @return [String] the fqdn-host
  class Sshfp
    attr_reader :cipher, :digest, :key, :rectype
    attr_accessor :host

    # This constructor initializes cipher, key, digest, host and keyfile
    # If keyfile was provided, the key will automatically read from file
    #
    # @param [Hash] args the options to initialize the object with
    # @option args [Integer] digest sha1 = 1, sha256 = 2
    # @option args [String] host fqdn of the host
    # @option args [String] keyfile path to the keyfile
    def initialize(args = {})
      @cipher = nil
      @key = nil
      self.digest = args.fetch(:digest, 2)
      @host = args.fetch(:host, 'localhost')
      keyfile = args.fetch(:keyfile, nil)
      @rectype = 'SSHFP'
      read_file(keyfile) unless keyfile.nil?
    end

    # This setter initializes cipher
    #
    # @param [Integer] val the key-cipher.
    # ssh-rsa = 1, ssh-dss = 2, ecdsa = 3 and ed25519 = 4
    # @raise Cryptorecord::ArgumentError
    def cipher=(val)
      if val.to_i < 1 || val.to_i > 4
        raise ArgumentError, 'Invalid cipher. Has to be 0,1,2,3 or 4'
      end

      @cipher = val
    end

    # This setter initializes the hash-algo
    #
    # @param [Integer] val digest. sha1 = 1, sha256 = 2
    # @raise Cryptorecord::ArgumentError
    def digest=(val)
      unless val.to_i == 1 || val.to_i == 2
        raise ArgumentError, 'Invalid digest. Has to be 1 or 2'
      end
      @digest = val
    end

    # This function reads in the key from file and
    # initializes the cipher- and key-variable
    # @param [String] keyfile path to the ssh-hostkey-file
    # @raise Cryptorecord::ArgumentError
    def read_file(keyfile)
      raise ArgumentError, 'No hostkey-file defined' if keyfile.nil?

      data = File.read(keyfile)
      (type, @key) = data.split(' ')
      cipher_by_type(type)
    end

    # this function creates a Hash-String
    #
    # @return [String] Hash-string of the key
    # @raise Cryptorecord::KeyError
    def fingerprint
      raise Cryptorecord::KeyError, 'No certificate defined' if @key.nil?

      case @digest.to_i
      when 1
        return OpenSSL::Digest::SHA1.new(Base64.strict_decode64(@key)).to_s
      when 2
        return OpenSSL::Digest::SHA256.new(Base64.strict_decode64(@key)).to_s
      end
    end

    # This method returns the left-hand name of a dns-record
    # @return [String] left-hand name of a dns-record
    def left
      "#{@host}."
    end

    # This method returns the right-hand content of a dns-record
    # @return [String] right-hand content of a dns-record
    def right
      "#{@cipher} #{@digest} #{fingerprint}"
    end

    # This method concats the sshfp-record
    #
    # @return [String] sshfp dns-record as defined in rfc4255
    # @raise Cryptorecord::KeyError
    def to_s
      raise Cryptorecord::KeyError, 'No certificate defined' if @key.nil?
      "#{left} IN #{@rectype} #{right}"
    end

    private

    # This helper-function selects the cipher using the given
    # type
    #
    # @param [String] type ssh-rsa = 1, ssh-dss = 2,
    # ecdsa-sha2-nistp256 = 3, ssh-ed25519 = 4
    # @raise Cryptorecord::CipherError
    # @return [Integer] integer value of the cipher
    def cipher_by_type(type)
      case type
      when 'ssh-rsa'
        self.cipher = 1
      when 'ssh-dss'
        self.cipher = 2
      when 'ecdsa-sha2-nistp256'
        self.cipher = 3
      when 'ssh-ed25519'
        self.cipher = 4
      else
        raise Cryptorecord::CipherError, 'Unsupported cipher'
      end
    end
  end
end
