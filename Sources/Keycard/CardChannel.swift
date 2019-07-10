protocol CardChannel {
    var connected: Bool { get }
    func send(_ cmd: APDUCommand) throws -> APDUResponse
}

extension CardChannel {
    var pairingPasswordPBKDF2IterationCount: Int {
        return 50000;
    }
}
