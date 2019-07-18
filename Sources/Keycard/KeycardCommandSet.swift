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

    func unblockPIN(puk: String, newPIN: String) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.unblockPIN.rawValue, p1: 0, p2: 0, data: Array((puk + newPIN).utf8))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func loadKey(seed: [UInt8]) throws -> APDUResponse {
        try loadKey(p1: LoadKeyP1.seed.rawValue, data: seed)
    }
    
    func loadKey(privateKey: [UInt8], chainCode: [UInt8]?, publicKey: [UInt8]?) throws -> APDUResponse {
        try loadKey(keyPair: BIP32KeyPair(privateKey: privateKey, chainCode: chainCode, publicKey: publicKey), omitPublic: publicKey == nil)
    }
    
    func loadKey(keyPair: BIP32KeyPair, omitPublic: Bool = false) throws -> APDUResponse {
        let p1 = keyPair.isExtended ? LoadKeyP1.extEC.rawValue : LoadKeyP1.ec.rawValue
        return try loadKey(p1: p1, data: keyPair.toTLV(includePublic: !omitPublic))
    }
    
    func loadKey(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.loadKey.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func generateMnemonic(length: GenerateMnemonicP1) throws -> APDUResponse {
        try generateMnemonic(p1: length.rawValue)
    }
    
    func generateMnemonic(p1: UInt8) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.generateMnemonic.rawValue, p1: p1, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func removeKey() throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.removeKey.rawValue, p1: 0, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func generateKey() throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.generateKey.rawValue, p1: 0, p2: 0, data: [])
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func duplicateKeyStart(entropyCount: UInt8, firstEntropy: [UInt8]) throws -> APDUResponse {
        try duplicateKey(p1: DuplicateKeyP1.start.rawValue, p2: entropyCount, data: firstEntropy)
    }
    
    func duplicateKeyAddEntropy(entropy: [UInt8]) throws -> APDUResponse {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.duplicateKey.rawValue, p1: DuplicateKeyP1.addEntropy.rawValue, p2: 0, data: secureChannel.oneShotEncrypt(data: entropy))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func duplicateKeyExport() throws -> APDUResponse {
        try duplicateKey(p1: DuplicateKeyP1.exportKey.rawValue, p2: 0, data: [])
    }
    
    func duplicateKeyImport(key: [UInt8]) throws -> APDUResponse {
        try duplicateKey(p1: DuplicateKeyP1.importKey.rawValue, p2: 0, data: key)
    }
    
    func duplicateKey(p1: UInt8, p2: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.duplicateKey.rawValue, p1: p1, p2: p2, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func sign(hash: [UInt8]) throws -> APDUResponse {
        try sign(p1: SignP1.currentKey.rawValue, data: hash)
    }
    
    func sign(hash: [UInt8], path: String, makeCurrent: Bool) throws -> APDUResponse {
        let path = try KeyPath(path)
        let p1 = (makeCurrent ? SignP1.deriveAndMakeCurrent.rawValue : SignP1.currentKey.rawValue) | path.source.rawValue
        return try sign(p1: p1, data: (hash + path.data))
    }
    
    func signPinless(hash: [UInt8]) throws -> APDUResponse {
        try sign(p1: SignP1.pinless.rawValue, data: hash)
    }
    
    func sign(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.sign.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    func deriveKey(path: String) throws -> APDUResponse {
        let path = try KeyPath(path)
        return try deriveKey(p1: path.source.rawValue, data: path.data)
    }
    
    func deriveKey(p1: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.deriveKey.rawValue, p1: p1, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func setPinlessPath(path: String) throws -> APDUResponse {
        let path = try KeyPath(path)
        precondition(path.source == DeriveKeyP1.fromMaster)
        
        return try setPinlessPath(data: path.data)
    }
    
    func resetPinlessPath() throws -> APDUResponse {
        try setPinlessPath(data: [])
    }
    
    func setPinlessPath(data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.setPinlessPath.rawValue, p1: 0, p2: 0, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }

    func exportCurrentKey(publicOnly: Bool) throws -> APDUResponse {
        let p2 = publicOnly ? ExportKeyP2.publicOnly.rawValue : ExportKeyP2.privateAndPublic.rawValue
        return try exportKey(p1: ExportKeyP1.currentKey.rawValue, p2: p2, data: [])
    }
    
    func exportKey(path: String, makeCurrent: Bool, publicOnly: Bool) throws -> APDUResponse {
        let path = try KeyPath(path)
        let p1 = (makeCurrent ? ExportKeyP1.deriveAndMakeCurrent.rawValue : ExportKeyP1.deriveAndMakeCurrent.rawValue) | path.source.rawValue
        let p2 = publicOnly ? ExportKeyP2.publicOnly.rawValue : ExportKeyP2.privateAndPublic.rawValue
        return try exportKey(p1: p1, p2: p2, data: path.data)
    }
    
    func exportKey(p1: UInt8, p2: UInt8, data: [UInt8]) throws -> APDUResponse {
        let cmd = secureChannel.protectedCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.exportKey.rawValue, p1: p1, p2: p2, data: data)
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
    
    func initialize(pin: String, puk: String, pairingPassword: String) throws -> APDUResponse {
        try initialize(pin: pin, puk: puk, sharedSecret: pairingPasswordToSecret(password: pairingPassword))
    }
    
    func initialize(pin: String, puk: String, sharedSecret: [UInt8]) throws -> APDUResponse {
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.initialize.rawValue, p1: 0, p2: 0, data: secureChannel.oneShotEncrypt(data: (Array((pin + puk).utf8) + sharedSecret)))
        return try secureChannel.transmit(channel: cardChannel, cmd: cmd)
    }
}
