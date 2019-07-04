/**
 * ISO7816-4 APDU.
 */
struct APDUCommand {
    let cla: UInt8
    let ins: UInt8
    let p1: UInt8
    let p2: UInt8
    let data: [UInt8]
    let needsLE: Bool
    
    init(cla: UInt8, ins: UInt8, p1: UInt8, p2: UInt8, data: [UInt8] = [], needsLE: Bool = false) {
        self.cla = cla;
        self.ins = ins;
        self.p1 = p1;
        self.p2 = p2;
        self.data = data;
        self.needsLE = needsLE;
    }
    
    func serialize() -> [UInt8] {
        let header = [cla, ins, p1, p2, UInt8(data.count)]
        let footer = needsLE ? [UInt8(0)] : []
        return header + data + footer
    }
}
