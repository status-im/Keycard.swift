import Foundation

public class CashCommandSet {
    let cardChannel: CardChannel
    
    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
    }
    
    public func select() throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.keycardCashInstanceAID.val)
        return try cardChannel.send(selectApplet)
    }
    
    public func sign(data: [UInt8]) throws -> APDUResponse {       
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.sign.rawValue, p1: 0, p2: 0, data: data)
        return try cardChannel.send(cmd)
    }
}

