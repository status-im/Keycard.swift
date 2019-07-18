class SecureChannel {
    static let secretLength = 32
    static let blockLength = 16

    var open: Bool
    var publicKey: [UInt8]?
    var pairing: Pairing?
    
    private var iv: [UInt8]
    
    func generateSecret(pubKey: [UInt8]) {
        //TODO: implement
    }

    func reset() {
        open = false
    }
    
    init() {
        open = false
        iv = []
    }
    
    func autoOpenSecureChannel(channel: CardChannel) throws {
        //TODO: implement
    }
 
    func autoPair(channel: CardChannel, secret: [UInt8]) throws {
        //TODO: implement
    }
    
    func autoUnpair(channel: CardChannel) throws {
        //TODO: implement
    }
    
    func unpairOthers(channel: CardChannel) throws {
        //TODO: implement
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
        //TODO: implement
        APDUCommand(cla: cla, ins: ins, p1: p1, p2: p2, data: data)
    }
    
    func transmit(channel: CardChannel, cmd: APDUCommand) throws -> APDUResponse {
        let rsp = try channel.send(cmd)
        //TODO: implement
        return rsp
    }
    
    func oneShotEncrypt(data: [UInt8]) -> [UInt8] {
        []
    }
}
