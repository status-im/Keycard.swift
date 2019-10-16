import Foundation

public class CashCommandSet {
    let cardChannel: CardChannel
    
    public func select() throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.keycardCashInstanceAID)
        return try cardChannel.send(selectApplet)
    }
    
    public func sign(data: [UInt8]) throws -> APDUResponse {
        Logger.shared.log("sign data=\(Data(data).toHexString())")
        
        let cmd = APDUCommand(cla: CLA.proprietary.rawValue, ins: KeycardINS.sign.rawValue, p1: 0, p2: 0, data: data)
        return try cardChannel.send(cmd)
    }
}

