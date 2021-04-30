import Foundation

public class SCP02 {
    public static let zeroIV: [UInt8] = [UInt8](repeating: 0, count: 8)
    
    static let derivationPurposeEnc: [UInt8] = [0x01, 0x82]
    static let derivationPurposeMac: [UInt8] = [0x01, 0x01]
    static let derivationPurposeDek: [UInt8] = [0x01, 0x81]

    var cardChallenge: [UInt8]
    var encKey: [UInt8]
    var macKey: [UInt8]
    var dataKey: [UInt8]
    var icv: [UInt8]

    let cardChannel: CardChannel
    
    public init(channel: CardChannel) {
        cardChannel = channel
        cardChallenge = []
        encKey = []
        macKey = []
        dataKey = []
        icv = SCP02.zeroIV
    }
    
    public func send(_ cmd: APDUCommand) throws -> APDUResponse {
        return try cardChannel.send(wrap(cmd))
    }
    
    public func verifyChallenge(hostChallenge: [UInt8], key: [UInt8], cardResponse: [UInt8]) -> Bool {
        if (cardResponse.count != 28) {
            return false
        }
        
        cardChallenge = Array(cardResponse[12..<20])

        let seq: [UInt8] = Array(cardResponse[12..<14])
        let cardCryptogram: [UInt8] = Array(cardResponse[20..<28])
        
        encKey = deriveSessionKey(key: key, seq: seq, purpose: SCP02.derivationPurposeEnc)
        macKey = deriveSessionKey(key: key, seq: seq, purpose: SCP02.derivationPurposeMac)
        dataKey = deriveSessionKey(key: key, seq: seq, purpose: SCP02.derivationPurposeDek)
        icv = SCP02.zeroIV

        return verifyCryptogram(hostChallenge: hostChallenge, cardCryptogram: cardCryptogram)
    }
    
    public func generateHostCryptogram(hostChallenge: [UInt8]) -> [UInt8] {
        return generateCryptogram(challenge1: cardChallenge, challenge2: hostChallenge)
    }
    
    public func generateCryptogram(challenge1: [UInt8], challenge2: [UInt8]) -> [UInt8] {
        var data: [UInt8] = []
        data.append(contentsOf: challenge1)
        data.append(contentsOf: challenge2)
        let paddedData = Crypto.shared.iso7816_4Pad(data: data, blockSize: 8)
        return Crypto.shared.des3Mac(data: paddedData, iv: SCP02.zeroIV, key: encKey)
    }
    
    func deriveSessionKey(key: [UInt8], seq: [UInt8], purpose: [UInt8]) -> [UInt8] {
        var derivationData: [UInt8] = [UInt8](repeating: 0, count: 16)
        derivationData[0] = purpose[0]
        derivationData[1] = purpose[1]
        derivationData[2] = seq[0]
        derivationData[3] = seq[1]
        
        var derivedKey: [UInt8] = Crypto.shared.des3Enc(data: derivationData, iv: SCP02.zeroIV, key: key)
        derivedKey.append(contentsOf: Crypto.shared.resizeDESKey8(derivedKey))
        return derivedKey
    }
    
    func verifyCryptogram(hostChallenge: [UInt8], cardCryptogram: [UInt8]) -> Bool {
        let calculated: [UInt8] = generateCryptogram(challenge1: hostChallenge, challenge2: cardChallenge)
        return calculated == cardCryptogram
    }
    
    func wrap(_ cmd: APDUCommand) -> APDUCommand {
        let cla: UInt8 = cmd.cla | 0x04
        var macData: [UInt8] = [cla, cmd.ins, cmd.p1, cmd.p2, UInt8(cmd.data.count + 8)]
        macData.append(contentsOf: cmd.data)
        
        if (icv != SCP02.zeroIV) {
            icv = Crypto.shared.desEnc(data: icv, iv: SCP02.zeroIV, key: Crypto.shared.resizeDESKey8(macKey))
        }
        
        let mac: [UInt8] = Crypto.shared.des3FullMac(data: Crypto.shared.iso7816_4Pad(data: macData, blockSize: 8), iv: icv, key: macKey)
        var wrappedData: [UInt8] = []
        wrappedData.append(contentsOf: cmd.data)
        wrappedData.append(contentsOf: mac)
        
        icv = mac
        return APDUCommand(cla: cla, ins: cmd.ins, p1: cmd.p1, p2: cmd.p2, data: wrappedData, needsLE: cmd.needsLE)
    }
}
