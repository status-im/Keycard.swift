class KeycardCommandSet {
    let cardChannel: CardChannel
    let secureChannel: SecureChannel
    var info: ApplicationInfo?

    init(cardChannel: CardChannel) {
        self.cardChannel = cardChannel
        self.secureChannel = SecureChannel()
    }

    func select(instanceIdx: UInt8 = 1) throws -> APDUResponse {
        let selectApplet: APDUCommand = APDUCommand(cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x00, data: Identifier.getKeycardInstanceAID(instanceId: instanceIdx))
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
}
