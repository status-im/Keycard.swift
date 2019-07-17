class KeycardCommandSet {
    let cardChannel: CardChannel
    let secureChannel: SecureChannel
    var info: ApplicationInfo?
    var pairing: Pairing? { get { secureChannel.pairing } set { secureChannel.pairing = newValue }}

    init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SecureChannel()
    }
    
    func pairingPasswordToSecret(password: String) -> [UInt8] {
        Crypto.shared.pbkdf2(password: password, salt: Array("Keycard Pairing Password Salt".utf8), iterations: cardChannel.pairingPasswordPBKDF2IterationCount, outLen: SecureChannel.secretLength)
    }

    func select(instanceIdx: UInt8 = 1) throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.getKeycardInstanceAID(instanceId: instanceIdx))
        let resp: APDUResponse = try cardChannel.send(selectApplet)

        if resp.sw == StatusWord.ok.rawValue {
            info = try ApplicationInfo(resp.data)

            if (info!.hasSecureChannelCapability) {
                secureChannel.generateSecret(pubKey: info!.secureChannelPubKey)
                secureChannel.reset()
            }
        }

        return resp
    }
    
    func autoOpenSecureChannel() throws {
        try secureChannel.autoOpenSecureChannel(channel: cardChannel)
    }
    
    func autoPair(password: String) throws {
        try autoPair(secret: pairingPasswordToSecret(password: password))
    }
    
    func autoPair(secret: [UInt8]) throws {
        try secureChannel.autoPair(channel: cardChannel, secret: secret)
    }
    
    func autoUnpair() throws {
        try secureChannel.autoUnpair(channel: cardChannel)
    }
    
    func unpairOthers() throws {
        try secureChannel.unpairOthers(channel: cardChannel)
    }
    
    func openSecureChannel(index: UInt8, data: [UInt8]) throws -> APDUResponse {
        try secureChannel.openSecureChannel(channel: cardChannel, index: index, data: data)
    }
    
    func mutuallyAuthenticate() throws -> APDUResponse {
        try secureChannel.mutuallyAuthenticate(channel: cardChannel)
    }
    
    func mutuallyAuthenticate(data: [UInt8]) throws -> APDUResponse {
        try secureChannel.mutuallyAuthenticate(channel: cardChannel, data: data)
    }
    
    func pair(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        try secureChannel.pair(channel: cardChannel, p1: p1, data: data)
    }
    
    func unpair(p1: UInt8) throws -> APDUResponse {
        try secureChannel.unpair(channel: cardChannel, p1: p1)
    }
    
    func getStatus(info: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.getStatus.rawValue, p1: info, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func getStatus(ndef: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.setNDEF.rawValue, p1: 0, p2: 0, data: ndef)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func verifyPIN(pin: String) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.verifyPIN.rawValue, p1: 0, p2: 0, data: Array(pin.utf8))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func changePIN(pin: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.userPIN.rawValue, data: Array(pin.utf8))
    }
    
    func changePUK(puk: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.puk.rawValue, data: Array(puk.utf8))
    }
    
    func changePairingPassword(pairingPassword: String) throws -> APDUResponse {
        try changePIN(p1: ChangePINP1.pairingSecret.rawValue, data: pairingPasswordToSecret(password: pairingPassword))
    }
    
    func changePIN(type: UInt8, pin: String) throws -> APDUResponse {
        try changePIN(p1: type, data: Array(pin.utf8))
    }
    
    func changePIN(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.changePIN.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
}
