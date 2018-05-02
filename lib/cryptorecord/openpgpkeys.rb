#--
# Copyright (C) 2018 Wolfgang Hotwagner <code@feedyourhead.at>       
#                                                                
# This file is part of the cryptorecord gem                                            
# 
# This mindwave gem is free software; you can redistribute it and/or 
# modify it under the terms of the GNU General Public License 
# as published by the Free Software Foundation; either version 2 
# of the License, or (at your option) any later version.
# 
# This mindwave gem is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License          
# along with this mindwave gem; if not, write to the 
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
class Openpgpkeys
# @!attribute [r] uid
#  stores the user-id
# @!attribute [r] key
#  stores the pgp-key
# @!attribute [r] localpart
#  stores the sha256-hash of the email-localpart
  attr_reader :uid, :domain, :key, :localpart
	
# This constructor initializes domain, uid and key
#
# @param [String|Mail::Address] uid email-address associated with the pgp-key
# @param [String] key pgp-key
  def initialize(args={})
      self.uid = args.fetch(:uid, nil)
      self.key = args.fetch(:key, nil)
  end

# This setter initializes the uid with an Mail::Address-object. Make
# sure this is the proper uid for the pgp-key!
#
# @param [String|Mail::Address] val The email-address without brackets 
  def uid=(val)
      if val.nil?
          @uid = nil
          return
      end
        
      case val
      when String
          @uid = Mail::Address.new("<#{val}>") if val.is_a?String
      when Mail::Address
          @uid = Mail::Address.new("<#{val.address}>")
      else
          raise "Unsupported datatype #{val.class.to_s} for val"
      end
  end

# This getter returns the SHA256sum of the uid-local-part(email-address) as defined
# in rfc7929
#
# @returns [String] the local-part of the keys uid(email-address) as SHA256 reduced to 56bytes or nil
  def localpart
      if @uid.nil?
          return nil
      else
          return OpenSSL::Digest::SHA256.new(@uid.local.to_s).to_s[0..55]
      end
  end

# This getter returns the domain-part of the uid(email-address) or nil
#
# @returns [String] domain the domain-part of the keys uid(email-address)
  def domain
      if @uid.nil?
          return nil
      else
          return @uid.domain
      end
  end

# This function trims the pgpkey so that all headers, footers, blanklines, and stuff
# are gone
#
# @param [String] val onne line of the pgpkey-block
#
# @returns An empty string if something has to be trimmed, otherwise the line itself
  def trimpgpkey(val)
      case val
      when '-----BEGIN PGP PUBLIC KEY BLOCK-----'
          return ''
      when  '-----END PGP PUBLIC KEY BLOCK-----'
          return ''
      when  "^\s*\n$"
          return ''
      end
        
      return val
  end

# This method sets the pgp-key
#
# @param [String] val PGP-Public-Key-Block
  def key=(val)
      return if val.nil?
        
      @key = String.new
      val.split(/\n/).each do |x|
      	@key += "#{self.trimpgpkey(x)}"
      end
      @key = @key.gsub(/=.{4}$/,"")
  end

# This method reads the pgp-key from a given file
#
# @param [String] keyfile Path to the keyfile
  def read_gpgkeyfile(keyfile)
    if(keyfile == nil)
      raise 'No keyfile defined'
    end
    data = File.read(keyfile)
    self.key = data
  end

# This method prints the openpgpkey-record to stdout
  def print
    puts self
  end

# This method concats the openpgpkey-record
#
# @returns [String] openpgpkey dns-record as defined in rfc7929
  def to_s
    "#{self.localpart}._openpgpkey.#{self.domain}. IN OPENPGPKEY #{@key}"
  end
end
end

