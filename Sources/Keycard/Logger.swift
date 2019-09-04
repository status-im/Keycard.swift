
import Foundation

open class Logger {

    static var shared: Logger = Logger()

    public init() {}

    func log(_ str: String) {
        print(str)
    }
}
