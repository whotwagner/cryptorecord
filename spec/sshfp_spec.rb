require "spec_helper"

require "cryptorecord/sshfp"

describe Cryptorecord::Sshfp do
  
  it "empty instances can be created" do
    sshfp = Cryptorecord::Sshfp.new
  end

  it "creates valid rsa records with hash-algo sha1" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 1, :keyfile => 'resources/ssh_host_rsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 1 1 057306ef954ce2c49bfcff70b0e29065a734b31e")
  end

  it "creates valid rsa records with hash-algo sha256" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 2, :keyfile => 'resources/ssh_host_rsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 1 2 6d0f092be13c975c36d8d454bb92e683fb9c8f4a40a16bbf98c836f297dc0d0e")
  end

  it "creates valid dsa records with hash-algo sha1" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 1, :keyfile => 'resources/ssh_host_dsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 2 1 2bfa2669b0de9a8a66b256b7df1d482db4861e9f")
  end

  it "creates valid dsa records with hash-algo sha256" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 2, :keyfile => 'resources/ssh_host_dsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 2 2 b3369b3906e267ff8ee9572b1352c40de1cf8b2bcef9f145bac7f9c9f6df91e6")
  end

  it "creates valid ecdsa records with hash-algo sha1" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 1, :keyfile => 'resources/ssh_host_ecdsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 3 1 e1f1a458cbfb94ee8b2d7669917ab87c6eabf901")
  end

  it "creates valid ecdsa records with hash-algo sha256" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 2, :keyfile => 'resources/ssh_host_ecdsa_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 3 2 a32b1eddd4ea9dcfbc377daa3eaf0ec43b3860b236dcedf1ee0c3d18babdf598")
  end

  it "creates valid ed25519 records with hash-algo sha1" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 1, :keyfile => 'resources/ssh_host_ed25519_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 4 1 a9a7a448495a217e32b332ae183a0d7a3d845858")
  end

  it "creates valid ed25519 records with hash-algo sha256" do
    sshfp = Cryptorecord::Sshfp.new(:digest => 2, :keyfile => 'resources/ssh_host_ed25519_key.pub', :host => 'www.example.com')
    expect(sshfp.to_s).to eq("www.example.com. IN SSHFP 4 2 2c4e9c2c123fb294da8b59fdb3e4d114847e3128a0f331df8132d8fdddbbd2b4")
  end

  it "raises exception if cipher is lower than 0" do
    sshfp = Cryptorecord::Sshfp.new
    expect{sshfp.cipher = -1}.to raise_error(Cryptorecord::ArgumentError)
  end

  it "raises exception if cipher is bigger than 4" do
    sshfp = Cryptorecord::Sshfp.new
    expect{sshfp.cipher = 5}.to raise_error(Cryptorecord::ArgumentError)

  end

  it "raises exception if digest is lower than 1" do
    sshfp = Cryptorecord::Sshfp.new
    expect{sshfp.digest = 0}.to raise_error(Cryptorecord::ArgumentError)
  end

  it "raises exception if digest is bigger than 2" do
    sshfp = Cryptorecord::Sshfp.new
    expect{sshfp.digest = 3}.to raise_error(Cryptorecord::ArgumentError)
  end

  it "raises exception if read_file is called with nil" do
    sshfp = Cryptorecord::Sshfp.new
    expect{sshfp.read_file(nil)}.to raise_error(Cryptorecord::ArgumentError)
    expect{sshfp.digest = 3}.to raise_error(Cryptorecord::ArgumentError)
  end

  it "unsupported cipher raises Cryptorecord::CipherError" do
    expect{sshfp = Cryptorecord::Sshfp.new(:digest => 2, :keyfile => 'resources/ssh_host_unsupported_key.pub', :host => 'www.example.com')}.to raise_error(Cryptorecord::CipherError)
  end


end
