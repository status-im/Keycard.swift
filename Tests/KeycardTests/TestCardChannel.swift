@testable import Keycard

class TestCardChannel: CardChannel {
    var callback: ((APDUCommand) throws -> APDUResponse)?
    var connected: Bool { get { true } }
    
    func send(_ cmd: APDUCommand) throws -> APDUResponse {
        if callback != nil {
            return try callback!(cmd)
        } else {
            throw CardError.communicationError
        }
    }
}
