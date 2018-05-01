module Cryptorecord

require 'openssl'
require 'mail'

class Openpgpkeys
	attr_reader :uid, :domain, :key, :localpart
	
	def initialize(args={})
		self.domain = args.fetch(:domain,"localhost")
		self.uid = args.fetch(:uid,nil)
		self.key = args.fetch(:key,nil)
	end

	def uid=(val)
		if val.nil?
			@uid = nil
			@localpart = nil
			self.domain = nil
			return
		end

		@uid = Mail::Address.new("<#{val}>")
		@localpart = OpenSSL::Digest::SHA256.new(@uid.local.to_s).to_s[0..55]
		self.domain = @uid.domain
	end

	def domain=(val)
		@domain = val
	end

	def key=(val)
		if (val.nil?)
			@key = nil
			return
		end
		@key = String.new
		arr = val.split(/\n/)
		arr.each do |x|
			next if x == "-----BEGIN PGP PUBLIC KEY BLOCK-----"
			next if x == "-----END PGP PUBLIC KEY BLOCK-----"
			next if x == "\s*\n"
			@key += "#{x}"
		end
		@key = @key.gsub(/=.{4}$/,"")
	end

	def read_gpgkeyfile(keyfile)
		if(keyfile == nil)
			raise "No keyfile defined"
		end
		data = File.read(keyfile)
		self.key = data
	end

	def print
		puts self
	end

	def to_s
		"#{@localpart}._openpgpkey.#{@domain}. IN OPENPGPKEY #{@key}"
	end
end

end
