class SecureChannel {
    static let secretLength = 32
    static let blockLength = 16
    static let pairingMaxClientCount = 5
    static let payloadMaxSize = 223

    var open: Bool
    var publicKey: [UInt8]?
    var pairing: Pairing?
    var secret: [UInt8]?
    
    private var iv: [UInt8]
    private var sessionEncKey: [UInt8]
    private var sessionMacKey: [UInt8]
    
    func generateSecret(pubKey: [UInt8]) {
        let (clientPubKey, privKey) = Crypto.shared.secp256k1GeneratePair()
        self.publicKey = clientPubKey
        self.secret = Crypto.shared.secp256k1ECDH(privKey: privKey, pubKey: pubKey)
    }

    func reset() {
        open = false
    }
    
    init() {
        open = false
        iv = []
        sessionEncKey = []
        sessionMacKey = []
    }
    
    func autoOpenSecureChannel(channel: CardChannel) throws {
        if (pairing == nil) {
            throw CardError.notPaired
        }
        
        var resp = try self.openSecureChannel(channel: channel, index: pairing!.pairingIndex, data: self.publicKey!).checkOK()
        processOpenSecureChannelResponse(resp)
        
        resp = try mutuallyAuthenticate(channel: channel).checkOK()
        
        if !verifyMutuallyAuthenticateResponse(resp) {
            throw CardError.invalidAuthData
        }
    }
    
    func processOpenSecureChannelResponse(_ response: APDUResponse) {
        let keyData = Array(response.data[0..<SecureChannel.secretLength])
        iv = Array(response.data[SecureChannel.secretLength...])
        
        let fullKey = Crypto.shared.sha512(self.secret! + pairing!.pairingKey + keyData)
        self.sessionEncKey = Array(fullKey[0..<SecureChannel.secretLength])
        self.sessionMacKey = Array(fullKey[SecureChannel.secretLength...])
        self.open = true
    }
    
    func verifyMutuallyAuthenticateResponse(_ response: APDUResponse) -> Bool {
        response.data.count == SecureChannel.secretLength;
    }
 
    func autoPair(channel: CardChannel, sharedSecret: [UInt8]) throws {
        let challenge = Crypto.shared.random(count: SecureChannel.secretLength)
        var resp = try self.pair(channel: channel, p1: PairP1.firstStep.rawValue, data: challenge).checkOK()
        
        let cardCryptogram = Array(resp.data[0..<SecureChannel.secretLength])
        let cardChallenge = Array(resp.data[SecureChannel.secretLength...])
        let checkCryptogram = Crypto.shared.sha256(sharedSecret + challenge)
        
        if checkCryptogram != cardCryptogram {
            throw CardError.invalidAuthData
        }
        
        let clientCryptogram = Crypto.shared.sha256(sharedSecret + cardChallenge)
        
        resp = try self.pair(channel: channel, p1: PairP1.lastStep.rawValue, data: clientCryptogram).checkOK()
        
        let pairingKey = Crypto.shared.sha256(sharedSecret + Array(resp.data[1...]))
        self.pairing = Pairing(pairingKey: pairingKey, pairingIndex: resp.data[0])
    }
    
    func autoUnpair(channel: CardChannel) throws {
        _ = try unpair(channel: channel, p1: pairing!.pairingIndex).checkOK()
    }
    
    func unpairOthers(channel: CardChannel) throws {
        for i in 0..<SecureChannel.pairingMaxClientCount {
            if i != pairing!.pairingIndex {
                _ = try self.unpair(channel: channel, p1: UInt8(i)).checkOK()
            }
        }
    }
    
    func openSecureChannel(channel: CardChannel, index: UInt8, data: [UInt8]) throws -> APDUResponse {
        open = false
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: SecureChannelINS.openSecureChannel.rawValue, p1: index, p2: 0, data: data)
        return try channel.send(cmd)
    }
    
    func mutuallyAuthenticate(channel: CardChannel) throws -> APDUResponse {
        try self.mutuallyAuthenticate(channel: channel, data: Crypto.shared.random(count: SecureChannel.secretLength))
    }
    
    func mutuallyAuthenticate(channel: CardChannel, data: [UInt8]) throws -> APDUResponse {
        let cmd = self.protectedCommand(cla: CLA.proprietary.rawValue, ins: SecureChannelINS.mutuallyAuthenticate.rawValue, p1: 0, p2: 0, data: data)
        return try self.transmit(channel: channel, cmd: cmd)
    }
    
    func pair(channel: CardChannel, p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: SecureChannelINS.pair.rawValue, p1: p1, p2: 0, data: data)
        return try self.transmit(channel: channel, cmd: cmd)
    }
    
    func unpair(channel: CardChannel, p1: UInt8) throws -> APDUResponse {
        let cmd = self.protectedCommand(cla: CLA.proprietary.rawValue, ins: SecureChannelINS.unpair.rawValue, p1: p1, p2: 0, data: [])
        return try self.transmit(channel: channel, cmd: cmd)
    }
    
    func protectedCommand(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: [UInt8]) -> APDUCommand {
        let finalData: [UInt8];
        
        if open {
            let encrypted = encryptAPDU(data);
            let meta: [UInt8] = [cla, ins, p1, p2, UInt8(encrypted.count + SecureChannel.blockLength), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            updateIV(meta: meta, data: encrypted);
            
            finalData = iv + encrypted
        } else {
            finalData = data;
        }
        
        return APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: finalData)
    }
    
    func transmit(channel: CardChannel, cmd: APDUCommand) throws -> APDUResponse {
        let rsp = try channel.send(cmd)

        if rsp.sw == 0x6982 {
            open = false;
        }
        
        if open {
            let meta: [UInt8] = [UInt8(rsp.data.count), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            let mac = Array(rsp.data[0..<SecureChannel.blockLength])
            let data = Array(rsp.data[SecureChannel.blockLength...])
            let plainData = decryptAPDU(data)
            
            updateIV(meta: meta, data: data)
            
            if self.iv != mac {
                throw CardError.invalidMac
            }
            
            return APDUResponse(rawData: plainData)
        } else {
            return rsp;
        }
    }
    
    func oneShotEncrypt(data: [UInt8]) -> [UInt8] {
        self.iv = Crypto.shared.random(count: SecureChannel.blockLength)
        let encrypted = Crypto.shared.aes256Enc(data: data, iv: iv, key: secret!)
        return [UInt8(self.publicKey!.count)] + publicKey! + iv + encrypted
    }
    
    private func encryptAPDU(_ data: [UInt8]) -> [UInt8] {
        precondition(data.count <= SecureChannel.payloadMaxSize)
        return Crypto.shared.aes256Enc(data: Crypto.shared.iso7816_4Pad(data: data, blockSize: SecureChannel.blockLength), iv: self.iv, key: self.sessionEncKey)
    }
    
    private func decryptAPDU(_ data: [UInt8]) -> [UInt8] {
        Crypto.shared.iso7816_4Unpad(data: Crypto.shared.aes256Dec(data: data, iv: self.iv, key: self.sessionEncKey))
    }
    
    private func updateIV(meta: [UInt8], data: [UInt8]) {
        self.iv = Crypto.shared.aes256CMac(data: meta + data, key: self.sessionMacKey)
    }
}
