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
  # Cryptorecord::Tlsa-class generates
  # tlsa-dns-records.
  class Tlsa
    # @!attribute [r] selector
    # stores the selector
    # @!attribute [r] mtype
    # stores the match-type
    # @!attribute [r] usage
    # stores the usage
    # @!attribute cert
    # stores the x509 certificate
    attr_reader :selector, :mtype, :usage, :cert
    # @!attribute host
    # stores the fqdn for the record
    # @!attribute proto
    # stores the network protocol
    # @!attribute port
    # stores the network port
    attr_accessor :host, :proto, :port

    def initialize(args = {})
      self.mtype = args.fetch(:mtype, 1)
      self.selector = args.fetch(:selector, 0)
      @host = args.fetch(:host, 'localhost')
      @proto = args.fetch(:proto, 'tcp')
      @port = args.fetch(:port, 443)
      self.usage = args.fetch(:usage, 3)
      self.cert = args.fetch(:cert, nil)
    end

    # This setter initializes the selector
    #
    # @param [Integer] val Selector for the association.
    #  0 = Full Cert, 1 = SubjectPublicKeyInfo
    def selector=(val)
      if val.to_i < 0 || val.to_i > 1
        raise ArgumentError, 'Invalid selector. Has to be 0 or 1'
      end
      @selector = val
    end

    # This setter initializes the mtype
    #
    # @param [Integer] val The Matching Type of the association.
    # 0 = Exact Match, 1 = SHA-256, 2 = SHA-512
    def mtype=(val)
      if val.to_i < 0 || val.to_i > 2
        raise ArgumentError, 'Invalid match type.'\
	'Has to be 0,1 or 2'
      end
      @mtype = val
    end

    # This setter initializes the usage
    #
    # @param [Integer] val Usage for the association.
    #   0 = PKIX-CA, 1 = PKIX-EE, 2 = DANE-TA, 3 = DANE-EE
    def usage=(val)
      if val.to_i < 0 || val.to_i > 3
        raise ArgumentError, 'Invalid usage. Has to be 0,1,2 or 3'
      end
      @usage = val
    end

    # this setter initializes the certificate
    #
    # @param [OpenSSL::X509::Certificate] val the x509 certificate
    def cert=(val)
      unless val.is_a?(OpenSSL::X509::Certificate) || val.nil?
        raise ArgumentError, 'cert has to be a OpenSSL::X509::Certificate'
      end

      @cert = val
    end

    # This function reads in the certificate from file
    #
    # @param [String] file path to certificate-file
    def read_certfile(file)
      data = File.read(file)
      self.cert = OpenSSL::X509::Certificate.new(data)
    end

    # this function creates a hash-string defined by mtype and selector
    # @returns depending on mtype and selector a proper hash will be returned
    def fingerprint
      raise 'No certificate defined' if @cert.nil?

      case @mtype.to_i
      when 0
        return bin_to_hex(msg)
      when 1
        return OpenSSL::Digest::SHA256.new(msg).to_s
      when 2
        return OpenSSL::Digest::SHA512.new(msg).to_s
      else
        raise 'Invalid match type. Has to be 0, 1 or 2'
      end
    end

    # This method prints the tlsa-record to stdout
    def print
      puts self
    end

    # This method concats the tlsa-record
    #
    # @returns [String] tlsa dns-record as defined in rfc6698
    def to_s
      "_#{@port}._#{@proto}.#{@host}. IN TLSA"\
      " #{@usage} #{@selector} #{@mtype} #{fingerprint}"
    end

    private

    # This function selects the msg to hash using the selector
    #
    # @returns if selector = 0 it returns cert.to_der,
    # if selector = 1 it returns cert.public_key.to_der
    def msg
      case @selector.to_i
      when 0
        return @cert.to_der
      when 1
        return @cert.public_key.to_der
      end

      raise 'Invalid selector. Has to be 0 or 1'
    end

    # This helper-function converts binary data into hex
    #
    # @param [String] str Binary-string
    # @returns hex-string
    def bin_to_hex(str)
      str.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
    end
  end
end
