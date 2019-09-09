
import Foundation

open class Logger {

    static var shared: Logger = Logger()

    public var isEnabled = true

    public init() {}

    func log(_ str: String) {
        #if DEBUG
        guard isEnabled else { return }
        print(str)
        #endif
    }
}
