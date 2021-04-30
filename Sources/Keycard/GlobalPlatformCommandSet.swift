import Foundation

public class GlobalPlatformCommandSet {
    let cardChannel: CardChannel
    let secureChannel: SCP02
    
    public init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SCP02(channel: cardChannel)
    }
    
    public func select() throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: CLA.iso7816.rawValue, ins: ISO7816INS.select.rawValue, p1: 0x04, p2: 0x00, data: Identifier.isdInstanceAID.val)
        return try cardChannel.send(selectApplet)
    }
    
    public func initializeUpdate(hostChallenge: [UInt8]) throws -> APDUResponse {
        let initUpdate: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: GlobalPlatformINS.initializeUpdate.rawValue, p1: 0, p2: 0, data: hostChallenge)
        let resp: APDUResponse = try cardChannel.send(initUpdate)
        
        if (resp.sw == StatusWord.ok.rawValue) {
            if !secureChannel.verifyChallenge(hostChallenge: hostChallenge, key: GlobalPlatformKeys.statusKeys.val, cardResponse: resp.data) {
                if !secureChannel.verifyChallenge(hostChallenge: hostChallenge, key: GlobalPlatformKeys.defaultKeys.val, cardResponse: resp.data) {
                    throw CardError.invalidAuthData
                }
            }
        }
        
        return resp
    }
    
    public func externalAuthenticate(hostChallenge: [UInt8]) throws -> APDUResponse {
        let hostCryptogram = secureChannel.generateHostCryptogram(hostChallenge: hostChallenge)
        let externalAuth: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: GlobalPlatformINS.externalAuthenticate.rawValue, p1: 0x01, p2: 0, data: hostCryptogram)
        return try secureChannel.send(externalAuth)
    }
    
    public func openSecureChannel() throws {
        let hostChallenge: [UInt8] = Crypto.shared.random(count: 8)
        try initializeUpdate(hostChallenge: hostChallenge).checkOK()
        try externalAuthenticate(hostChallenge: hostChallenge).checkOK()
    }

    public func deleteKeycardInstance() throws -> APDUResponse {
        return try delete(aid: Identifier.getKeycardInstanceAID())
    }
    
    public func deleteCashInstance() throws -> APDUResponse {
        return try delete(aid: Identifier.keycardCashInstanceAID.val)
    }
    
    public func deleteNDEFInstance() throws -> APDUResponse {
        return try delete(aid: Identifier.ndefInstanceAID.val)
    }
    
    public func delete(aid: [UInt8]) throws -> APDUResponse {
        var data: [UInt8] = [0x4f]
        data.append(UInt8(aid.count))
        data.append(contentsOf: aid)
        let delete: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: GlobalPlatformINS.delete.rawValue, p1: 0, p2: 0, data: data)
        return try secureChannel.send(delete)
    }
    
    public func installKeycardInstance() throws -> APDUResponse {
        return try installForInstall(packageAID: Identifier.packageAID.val, appletAID: Identifier.keycardAID.val, instanceAID: Identifier.getKeycardInstanceAID(), params: [])
    }
    
    public func installCashInstance(cashData: [UInt8]) throws -> APDUResponse {
        return try installForInstall(packageAID: Identifier.packageAID.val, appletAID: Identifier.keycardCashAID.val, instanceAID: Identifier.keycardCashInstanceAID.val, params: cashData)
    }
    
    public func installNDEFInstance(ndefRecord: [UInt8]) throws -> APDUResponse {
        return try installForInstall(packageAID: Identifier.packageAID.val, appletAID: Identifier.ndefAID.val, instanceAID: Identifier.ndefInstanceAID.val, params: ndefRecord)
    }
    
    public func installForInstall(packageAID: [UInt8], appletAID: [UInt8], instanceAID: [UInt8], params: [UInt8]) throws -> APDUResponse {
        var data: [UInt8] = [UInt8(packageAID.count)]
        data.append(contentsOf: packageAID)
        data.append(UInt8(appletAID.count))
        data.append(contentsOf: appletAID)
        data.append(UInt8(instanceAID.count))
        data.append(contentsOf: instanceAID)
        data.append(0x01)
        data.append(0x00)
        data.append(UInt8(params.count + 2))
        data.append(0xc9)
        data.append(UInt8(params.count))
        data.append(contentsOf: params)
        data.append(0x00)
        
        let installForInstall: APDUCommand = APDUCommand(cla: CLA.proprietary.rawValue, ins: GlobalPlatformINS.install.rawValue, p1: 0x0c, p2: 0, data: data)
        return try secureChannel.send(installForInstall)
    }
}
