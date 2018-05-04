require "spec_helper"

require "cryptorecord/openpgpkeys"
require "cryptorecord/exceptions"

describe Cryptorecord::Openpgpkeys do
  
  it "empty instances can be created" do
    sshfp = Cryptorecord::Openpgpkeys.new
  end

  it "creates a valid domain from uid" do
    sshfp = Cryptorecord::Openpgpkeys.new(:uid => 'hacky@hacktheplanet.com')
    expect(sshfp.domain).to eq("hacktheplanet.com")
  end

  it "uid can be Mail::Address-type" do
    sshfp = Cryptorecord::Openpgpkeys.new
    u = Mail::Address.new("hacky@hacktheplanet.com")
    sshfp.uid = u
    expect(sshfp.domain).to eq("hacktheplanet.com")
  end

  it "creates a valid local-part from uid" do
    sshfp = Cryptorecord::Openpgpkeys.new(:uid => "hacky@hacktheplanet.com")
    expect(sshfp.localpart).to eq("f075fb8ed9e2525ad1a24086f6f77ca7dc095da9109202f835e16832")
  end


  it "creates a valid openpgpkey-record" do
    sshfp = Cryptorecord::Openpgpkeys.new(:uid => "hacky@hacktheplanet.com")
    sshfp.read_file("resources/hacky.asc")
    expect(sshfp.to_s).to eq("f075fb8ed9e2525ad1a24086f6f77ca7dc095da9109202f835e16832._openpgpkey.hacktheplanet.com. IN OPENPGPKEY mQENBFgvZGABCACwTYzgHylv8CDpJ+hommdbP1wCpmOLYxAqYDn8ievuUMVwDcR3erGIRc5fspWUbgxiTxl5/MVWpf1O4A2/AdNFSb1enyiA+HmgvgrYr4rOUhrCSWz16m0bMz8QfDSduHLhIl7UdMz6zdGuiGLugAaTMBvOk9v+5I/yhsbLq1m+J5ExhtEoTgHbDjorhR0tkO6sxI48T8k1GrOpg6ke1LmKvxpIBoF9mAeyGXpa2uMnvZAd+PRFrTLoOYIdB3e28ynO3id3wDJrJUCIWwRAor/jQBFnOHFd0rDU1tajvuFNWBihXyHLYWsZISCMwd+v0WqUY5GkuRFXJWMXWke0QzSPABEBAAG0JUV2aWwgSGFja2VyIDxoYWNreUBoYWNrdGhlcGxhbmV0LmNvbT6JAT4EEwECACgFAlgvZGACGwMFCQHhM4AGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFwejPJSBqQeDI4IAJlvH8vhXwpZuUTkESIp4dDfZpvuyhm7a9XjYi3Nbio8r/obJ/Wp6pwE75mnwthi4CHxeAi7b/L9BJsxCL4eor2GkU9HcrEPaed7Fn9TqOmA9q1572SqSGqVjA2ZF5UTJg4lMXIV+WRWBGB4Uu47XBnF47RbL15Srt9dCGhb0Wceax+j44Pt6GtjqUvquwm62aWhHlZMlaKiuvaCWe6saR/f5YF3/2wOAvKUpS+1LMoHs/63xmSjlryNQW2/C6GZduf/MNfgocLi206DJgurobGk+5DmW+4tPkrloJ3jUEWq2TXFRu/RT8Xcp4ocY94QTld9b35FMjuCTIX+92I7+eS5AQ0EWC9kYAEIAOPXBylACdPT3S0OzjuI1Vrpc7Hso/YQIblG3zL5xzH/A9BQKw9/fNY28wWd/A9qd8dBeHQzqJf88p9OyVtUrcdWqrBFgBwAH8WM5OwT1OturoFzVi5bXG+cpDLkkSM2WAXUCEWFeBTE1K9C+FSZBtWFM2+aLLhpi2JcnYbuBGYWCmf9qh+ClPaxVdpCfufl5YesfCTxdES4awTAEb8PjdLSe7ZQC6/2ZiD9rwz2ohrQBOKkIfVh5ecIRd5SXcJxZLs9opV+uUp+lJifprAnC1SE7JP8+GYX7Y/8UVgXBF3/9nj+XZcKNHXcjTR1IkVjHEqR/kwYXvnqsYMOTN2iXVcAEQEAAYkBJQQYAQIADwUCWC9kYAIbDAUJAeEzgAAKCRBcHozyUgakHoKUB/4j+pCmMzCSF/nn4tis3eTYOA8Z3d+ryFUw9Zs1apvGsOiLLCdTUNQUZaEIvVvaGPMXMKwgMSkuoKjKkVgrsU9SrEPeXC5GevOTw4bTzk2tKhvp646FdhSvNJLP/gF6DnPtSnPx+u+T4jYrfspWMBO9ajigjTnr4503efoZh1/X2hdlNEu7ucsbdkqyu+hBLRxIC+BwKR5ZZ767jQ72aQVrRGeFSAaZXzYkMFsDP3fGQUlDxdKAliXLo2z4JOSUx/8iaeEZ5Wv8p7tGRb5AiIB9dBRr+Ub29qJefdw2Ht2F+r6PLTXxvhGR6sOrF4/wMxGY8vCkau6UvH7MfxdSgWwO")
  end

 it "set uid to a hash-object should raise Cryptorecord::ArgumentError" do
   expect{sshfp = Cryptorecord::Openpgpkeys.new(:uid => Hash.new)}.to raise_error(Cryptorecord::ArgumentError)
 end

 it "calling read_file with nil should raise Cryptorecord::ArgumentError" do
   sshfp = Cryptorecord::Openpgpkeys.new(:uid => "hacky@hacktheplanet.com")
   expect{sshfp.read_file(nil)}.to raise_error(Cryptorecord::ArgumentError)
 end
end
