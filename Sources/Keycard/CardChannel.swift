public protocol CardChannel {
    var connected: Bool { get }
    func send(_ cmd: APDUCommand) throws -> APDUResponse
}

public extension CardChannel {
    var pairingPasswordPBKDF2IterationCount: Int {
        return 50000;
    }
}
