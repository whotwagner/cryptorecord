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
  require 'mail'
  # Cryptorecord::Openpgpkeys-class generates
  # openphpkeys-dns-records. Instances must have an
  # uid. The PGP-Key can be read from file
  # @!attribute [r] uid
  #   @return [Mail::Address] the userid or nil
  # @!attribute [r] key
  #   @return [String] the pgp-key as a string
  class Openpgpkeys
    attr_reader :uid, :key

    # This constructor initializes uid and key by calling the setters.
    # @see uid=
    #
    # @param [Hash] args the options to initialize the object with
    # @option args [String] uid email-address associated with the pgp-key
    # @option args [String] key pgp-key
    def initialize(args = {})
      self.uid = args.fetch(:uid, nil)
      self.key = args.fetch(:key, nil)
    end

    # This setter takes the argument val to create a Mail::Address-object.
    # The argument val can be a email-address-string or a Mail::Address-object.
    # Make sure this is the proper uid for the pgp-key!
    #
    # @param [String|Mail::Address] val The email-address without brackets
    # @raise Cryptorecord::ArgumentError
    def uid=(val)
      if val.nil?
        @uid = nil
        return
      end

      case val
      when String
        @uid = Mail::Address.new("<#{val}>")
      when Mail::Address
        @uid = Mail::Address.new("<#{val.address}>")
      else
        raise Cryptorecord::ArgumentError,
              "Unsupported datatype #{val.class} for val"
      end
    end

    # This getter returns the SHA256sum of the
    # uid-local-part(email-address) as defined
    # in rfc7929
    #
    # @return [String] the local-part of the keys
    #  uid(email-address) as SHA256 reduced to 56bytes or nil
    def localpart
      @uid.nil? ? nil : OpenSSL::Digest::SHA256.new(@uid.local.to_s).to_s[0..55]
    end

    # This getter returns the domain-part of the uid(email-address) or nil
    #
    # @return [String] domain the domain-part of the keys uid(email-address)
    def domain
      @uid.nil? ? nil : @uid.domain
    end

    # This method sets the pgp-key. It takes the public-key-block
    # and trims the header, blankline and checksum
    #
    # @param [String] val PGP-Public-Key-Block(ASCII Armor)
    #  as defined in rfc4880 section 6.2
    def key=(val)
      return if val.nil?

      @key = ''
      val.split(/\n/).each do |x|
        @key += trimpgpkey(x).to_s
      end
      @key = @key.gsub(/=.{4}$/, '')
    end

    # This method reads the pgp-key from a given file
    #
    # @param [String] keyfile Path to the keyfile
    # @raise Cryptorecord::ArgumentError
    def read_file(keyfile)
      raise Cryptorecord::ArgumentError, 'No keyfile defined' if keyfile.nil?
      data = File.read(keyfile)
      self.key = data
    end

    # This method returns the left-hand name of a dns-record
    # @return [String] left-hand name of a dns-record
    def left
      "#{localpart}._openpgpkey.#{domain}"
    end

    # This method concats the openpgpkey-record
    #
    # @return [String] openpgpkey dns-record as defined in rfc7929
    def to_s
      "#{left}. IN OPENPGPKEY #{@key}"
    end

    private

    # This function trims the pgpkey so that all headers, footers,
    # blanklines, and stuff
    # are gone
    #
    # @param [String] val onne line of the pgpkey-block
    #
    # @return An empty string if something has to be trimmed,
    # otherwise the line itself
    def trimpgpkey(val)
      case val
      when '-----BEGIN PGP PUBLIC KEY BLOCK-----'
        ''
      when  '-----END PGP PUBLIC KEY BLOCK-----'
        ''
      when  /^\s*\n$/
        ''
      else
        val.to_s
      end
    end
  end
end
