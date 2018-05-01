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
require 'base64'

# Cryptorecord::Sshfp-class generates
# sshfp-dns-records. The ssh-host-keys are
# read from files
class Sshfp
# @!attribute [r] [Integer] cipher
#   stores the cipher. ssh-rsa = 1, ssh-dss = 2, ecdsa = 3 and ed25519 = 4
# @!attribute [r] [Integer] digest
#   stores the digest. sha1 = 1, sha256 = 2
# @!attribute [r] [String] key
#   stores the ssh-host-key
	attr_reader :cipher, :digest, :key
# @!attribute [String] host
#   stores the fqdn-host
# @!attribute [String] hostkeyfile
#   stores the path to the hostkeyfile
	attr_accessor :host, :hostkeyfile
	
	def initialize(args={})
		@cipher = nil
		@key = nil
		self.digest = args.fetch(:digest,2)
		@host = args.fetch(:host,"localhost")
		@keyfile = args.fetch(:keyfile,nil)
		
		self.read_sshkeyfile unless @keyfile.nil?
	end

	def cipher=(val)
		if val.to_i < 1 or val.to_i > 4
				raise "Invalid cipher. Has to be 0,1,2,3 or 4"
		end

		@cipher = val
	end

	def digest=(val)
		if val.to_i < 1 or val.to_i > 2
				raise "Invalid digest. Has to be 1 or 2"
		end
		@digest = val
	end

	def bin_to_hex(s)
	    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
	end

	def read_sshkeyfile
		if(@keyfile == nil)
			raise "No hostkey-file defined"
		end

		data = File.read(@keyfile)
		(type,@key) = data.split(" ")
		case type
			when "ssh-rsa"
				self.cipher=1
			when "ssh-dss"
				self.cipher=2
			when "ecdsa-sha2-nistp256"
				self.cipher=3
			when "ssh-ed25519"
				self.cipher=4
			else
				raise "Unsupported cipher"
		end

	end

	def fingerprint

		self.read_sshkeyfile if @key.nil?
		
		case @digest.to_i
		        when 1
				return OpenSSL::Digest::SHA1.new(Base64.strict_decode64(@key)).to_s
			when 2
				return OpenSSL::Digest::SHA256.new(Base64.strict_decode64(@key)).to_s
			else
				raise "Invalid digest. Has to be 1 or 2"
		end
	end

	def print
		puts self
	end

	def to_s
		 self.read_sshkeyfile if @cipher.nil?
		"#{@host}. IN SSHFP #{@cipher} #{@digest} #{self.fingerprint}"
	end
end

end
