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

class Tlsa
	attr_reader :selector, :mtype, :usage
	attr_accessor :host, :proto, :port, :cert
	
	def initialize(args={})
		self.mtype = args.fetch(:mtype,1)
		self.selector = args.fetch(:selector,0)
		@host = args.fetch(:host,"localhost")
		@proto = args.fetch(:proto,"tcp")
		@port = args.fetch(:port,443)
		self.usage = args.fetch(:usage,3)
		self.cert = args.fetch(:cert,nil)
	end

	def selector=(val)
		if val.to_i < 0 or val.to_i > 1
				raise "Invalid selector. Has to be 0 or 1"
		end

		@selector = val
	end

	def mtype=(val)
		if val.to_i < 0 or val.to_i > 2
				raise "Invalid match type. Has to be 0,1 or 2"
		end
		@mtype = val
	end

	def usage=(val)
		if val.to_i < 0 or val.to_i > 3
			raise "Invalid usage. Has to be 0,1,2 or 3"
		end
		@usage = val
	end

	def bin_to_hex(s)
	    s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
	end

	def cert=(val)
		unless val.is_a? OpenSSL::X509::Certificate or val.nil?
			raise "cert has to be a OpenSSL::X509::Certificate"
		end

		@cert=val
	end

	def read_certfile(file)
		data = File.read(file)
		self.cert = OpenSSL::X509::Certificate.new(data)
	end

	def fingerprint
		if(@cert == nil)
			raise "No certificate defined"
		end
		
		digest = nil
		msg = nil

		case @selector.to_i
			when 0
				msg = @cert.to_der
			when 1
				msg = @cert.public_key.to_der
			else
				raise "Invalid selector. Has to be 0 or 1"
		end

		case @mtype.to_i
		        when 0
				return bin_to_hex(msg)
			when 1
				return OpenSSL::Digest::SHA256.new(msg).to_s
			when 2 
			 	return  OpenSSL::Digest::SHA512.new(msg).to_s
			else
				raise "Invalid match type. Has to be 0, 1 or 2"
		end
	end

	def print
		puts self
	end

	def to_s
		"_#{@port}._#{@proto}.#{@host}. IN TLSA #{@usage} #{@selector} #{@mtype} #{self.fingerprint}"
	end
end

end
