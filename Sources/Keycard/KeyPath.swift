  enum KeyPathError: Error {
        case tooManyComponents
        case invalidCharacters
  }
  
  struct KeyPath: CustomStringConvertible {
    let source: DeriveKeyP1
    var data: [UInt8]
    
    var description: String {
        get {
            var desc: String
            
            switch(source) {
            case .fromMaster:
                desc = "m"
            case .fromParent:
                desc = ".."
            case .fromCurrent:
                desc = "."
            }
            
            for rawComponent in data.chunked(into: 4) {
                desc.append("/")
                var num: UInt32
                
                num = UInt32(rawComponent[rawComponent.startIndex] & 0x7f) << 24
                num |= UInt32(rawComponent[rawComponent.startIndex + 1]) << 16
                num |= UInt32(rawComponent[rawComponent.startIndex + 2]) << 8
                num |= UInt32(rawComponent[rawComponent.startIndex + 3])
                
                desc.append(num.description)
                
                if (rawComponent[rawComponent.startIndex] & 0x80 == 0x80) {
                    desc.append("'")
                }
            }
            
            return desc
        }
    }

    init(_ keyPath: String) throws {
        let components = keyPath.split(separator: "/")
        var pathComponents = components.dropFirst()
        
        switch(components[0]) {
        case "m":
            self.source = DeriveKeyP1.fromMaster
        case "..":
            self.source = DeriveKeyP1.fromParent
        case ".":
            self.source = DeriveKeyP1.fromCurrent
        default:
            self.source = DeriveKeyP1.fromCurrent
            pathComponents = components[0...]
        }
        
        if pathComponents.count > 10 {
            throw KeyPathError.tooManyComponents
        }
        
        data = [UInt8]()
        
        for component in pathComponents {
            let pathInt = try parseComponent(component)
            data.append(UInt8((pathInt >> 24) & 0xff))
            data.append(UInt8((pathInt >> 16) & 0xff))
            data.append(UInt8((pathInt >> 8) & 0xff))
            data.append(UInt8(pathInt & 0xff))
        }
    }
    
    init(data: [UInt8], source: DeriveKeyP1 = DeriveKeyP1.fromMaster) {
        self.data = data
        self.source = source
    }
    
    private func parseComponent(_ component: Substring) throws -> UInt32 {
        if (component.hasPrefix("+") || component.hasPrefix("-")) {
            throw KeyPathError.invalidCharacters
        }

        var res: UInt32
        let numString: Substring
        
        if component.hasSuffix("'") {
            res = 0x80000000
            numString = component.dropLast()
        } else {
            res = 0
            numString = component
        }
        
        if let num = Int(numString) {
            res |= UInt32(num)
        } else {
            throw KeyPathError.invalidCharacters
        }
        
        return res
    }
}

