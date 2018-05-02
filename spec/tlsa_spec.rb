require "spec_helper"

require "cryptorecord/tlsa"

describe Cryptorecord::Tlsa do
  
  it "generates a valid tlsa record using defaults" do
    tlsa = Cryptorecord::Tlsa.new
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.localhost. IN TLSA 3 0 1 471f63a45f10b8e9c48acd91428bbb14bfa35ab07aecf61fde9f15f85bf9448b")
  end

  it "generates a valid tlsa record with 3 0 1" do
    selector = 0
    mtype = 1
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 0 1 471f63a45f10b8e9c48acd91428bbb14bfa35ab07aecf61fde9f15f85bf9448b")
  end


  it "generates a valid tlsa record with 3 1 1" do
    selector = 1
    mtype = 1
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 1 1 e32dcafc43a10c4824453b96be977bd533f39de38f18fbc1b6463260bab0d438")
  end

  it "generates a valid tlsa record with 3 1 0" do
    selector = 1
    mtype = 0
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 1 0 30820122300d06092a864886f70d01010105000382010f003082010a0282010100a817cf8c9dfab5dbafde69e3cf09a51bd436811a0131c4f6285affe5ebc1b6e3d445f4dadbb0bbefb24437932163b81a31182a3357530bc531d9143ee9385d5fc5fc759cdee42edd6eb743887b0c7de548731f76c03b0ad0a2c172dd57a664fb90a09cb62dc9257e09232ae34fa7c3c029a4f8cc5c0eceee83595dbddf5f0d2bfe7ba02bc3c8ed014675e87020d77048fc781f8e69b16a1b1fdf6f438f9b2208e663033fc65b83720d49f8c5be9170b6788f3772ff2012a8179fe45bcc40c61918d98eb8fe3959e4fa86c603267689e4ed254654198267f8eb6cce1b2c9cc75629fb93333fe05fe18717458df1eea00310d506689a4da1a40ca63c5fbe6999cd0203010001")
  end

  it "generates a valid tlsa record with 3 0 0" do
    selector = 0
    mtype = 0
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 0 0 308203bc308202a4a003020102020900e7235e4af7759093300d06092a864886f70d01010b05003073310b30090603550406130241553113301106035504080c0a536f6d652053746174653112301006035504070c09536f6d6520436974793121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643118301606035504030c0f7777772e6578616d706c652e636f6d301e170d3138303433303230323230345a170d3238303432373230323230345a3073310b30090603550406130241553113301106035504080c0a536f6d652053746174653112301006035504070c09536f6d6520436974793121301f060355040a0c18496e7465726e6574205769646769747320507479204c74643118301606035504030c0f7777772e6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100a817cf8c9dfab5dbafde69e3cf09a51bd436811a0131c4f6285affe5ebc1b6e3d445f4dadbb0bbefb24437932163b81a31182a3357530bc531d9143ee9385d5fc5fc759cdee42edd6eb743887b0c7de548731f76c03b0ad0a2c172dd57a664fb90a09cb62dc9257e09232ae34fa7c3c029a4f8cc5c0eceee83595dbddf5f0d2bfe7ba02bc3c8ed014675e87020d77048fc781f8e69b16a1b1fdf6f438f9b2208e663033fc65b83720d49f8c5be9170b6788f3772ff2012a8179fe45bcc40c61918d98eb8fe3959e4fa86c603267689e4ed254654198267f8eb6cce1b2c9cc75629fb93333fe05fe18717458df1eea00310d506689a4da1a40ca63c5fbe6999cd0203010001a3533051301d0603551d0e04160414e3413922c8c57c3e036d5df4f30c87756393121b301f0603551d23041830168014e3413922c8c57c3e036d5df4f30c87756393121b300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101000b0de991099fbdfcc8cf1d042de27d9a3a3998138a692dfcfbd6af025330a6c3624a65f374e889774e529b35e849ea5e8bcf935fa7763aaa5c674113facd44c19c7c9f7fd5b9fcd478dbc25c26df0ecbf579b4e593126ed8dde6c1c95e528eb1da3e2bec6a9e52b780ba077bd5841c609b442f552de7e78a7fb6d98b8fe355d41a57ae319770afaaa234fa1cd85f5ffbbbbfb141da2b09b15a4f7d834a61b572602a9f1de970371b28b8a8708a17d8328d3d6ef7f5b70701610754d6de6e0ec8c6753cf482b741a80954d1c17c4307010a3f5c1959c45c0349cf4657ee4387983cd6a6f6904717cd80341c0ea96d4d70163b0cca210323b078e951ac5a1fb17c")
  end


  it "generates a valid tlsa record with 3 0 2" do
    selector = 0
    mtype = 2
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 0 2 889301b47df57ba703136221b1755e5c54b6a861208fb162d09755a99d6b9a9d6ae02aa9f6c3845ad1bbdf75b1fccba58b770a7c53f191248c895adf354345f4")
  end

  it "generates a valid tlsa record with 3 1 2" do
    selector = 1
    mtype = 2
    usage = 3
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 3 1 2 1e0796a92f941fc2d6a12441a46295a3affc86aed2faddb49e0df38c07a871229ef9a9ed8e2231873a80e8e270810d608fef9ecef30a834c319ab32e37f10070")
  end

 it "generates a valid tlsa record with 2 0 1" do
    selector = 0
    mtype = 1
    usage = 2
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 2 0 1 471f63a45f10b8e9c48acd91428bbb14bfa35ab07aecf61fde9f15f85bf9448b")
  end

 it "generates a valid tlsa record with 1 0 1" do
    selector = 0
    mtype = 1
    usage = 1
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 1 0 1 471f63a45f10b8e9c48acd91428bbb14bfa35ab07aecf61fde9f15f85bf9448b")
  end

 it "generates a valid tlsa record with 0 0 1" do
    selector = 0
    mtype = 1
    usage = 0
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    tlsa.read_certfile("resources/server.cert")
    expect(tlsa.to_s).to eq("_443._tcp.www.example.com. IN TLSA 0 0 1 471f63a45f10b8e9c48acd91428bbb14bfa35ab07aecf61fde9f15f85bf9448b")
  end

 it "selector smaller than 0 must raise exception" do
    selector = -1
    mtype = 1
    usage = 0
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end

 it "selector bigger than 1 must raise exception" do
    selector = 2
    mtype = 1
    usage = 0
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end

 it "usage smaller than 0 must raise exception" do
    selector = 1
    mtype = 1
    usage = -1
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end


 it "usage bigger than 3 must raise exception" do
    selector = 1
    mtype = 1
    usage = 4
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end

 it "mtype smaller than 0 must raise exception" do
    selector = 1
    mtype = -1
    usage = 1
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end


 it "usage bigger than 2 must raise exception" do
    selector = 1
    mtype = 3
    usage = 1
    port = 443
    proto = "tcp"
    host = "www.example.com"
    expect{tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )}.to raise_error(Cryptorecord::ArgumentError)
  end

 it "cert other than nil or OpenSSL::X509::Certificate must raise exception" do
    selector = 1
    mtype = 1
    usage = 1
    port = 443
    proto = "tcp"
    host = "www.example.com"
    tlsa = Cryptorecord::Tlsa.new(:selector => selector, :mtype => mtype, :usage => usage, :port => port, :proto => proto, :host => host )
    expect{tlsa.cert = Hash.new}.to raise_error(Cryptorecord::ArgumentError)
  end


end
