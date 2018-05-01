module Cryptorecord

require 'openssl'
require 'base64'

class Sshfp
	attr_reader :cipher, :digest, :key
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
