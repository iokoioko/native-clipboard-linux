import Foundation

@objc(UASharedPasteboardInfoWrapper)
final class UASharedPasteboardInfoWrapper: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let pbInfo: UASharedPasteboardInfo
    let extraData: NSData
    let extraDataType: Int
    let protocolVersion: Int

    init(pbInfo: UASharedPasteboardInfo, extraData: Data, extraDataType: Int, protocolVersion: Int) {
        self.pbInfo = pbInfo
        self.extraData = extraData as NSData
        self.extraDataType = extraDataType
        self.protocolVersion = protocolVersion
        super.init()
    }

    required init?(coder: NSCoder) {
        guard
            let pbInfo = coder.decodeObject(of: UASharedPasteboardInfo.self, forKey: "UASharedPasteboardInfoWrapperPBInfoKey"),
            let extraData = coder.decodeObject(of: NSData.self, forKey: "UASharedPasteboardInfoWrapperExtraDataKey")
        else { return nil }
        self.pbInfo = pbInfo
        self.extraData = extraData
        self.extraDataType = coder.decodeInteger(forKey: "UASharedPasteboardInfoWrapperExtraTypeKey")
        self.protocolVersion = coder.decodeInteger(forKey: "UASharedPasteboardInfoWrapperProtocolVersionKey")
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(pbInfo, forKey: "UASharedPasteboardInfoWrapperPBInfoKey")
        coder.encode(extraData, forKey: "UASharedPasteboardInfoWrapperExtraDataKey")
        coder.encode(extraDataType, forKey: "UASharedPasteboardInfoWrapperExtraTypeKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardInfoWrapperErrorKey")
        coder.encode(protocolVersion, forKey: "UASharedPasteboardInfoWrapperProtocolVersionKey")
    }
}

@objc(UASharedPasteboardInfo)
final class UASharedPasteboardInfo: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let dataSize: Int
    let items: [UASharedPasteboardItemInfo]

    init(dataSize: Int, items: [UASharedPasteboardItemInfo]) {
        self.dataSize = dataSize
        self.items = items
        super.init()
    }

    required init?(coder: NSCoder) {
        guard let items = coder.decodeObject(
            of: [NSArray.self, UASharedPasteboardItemInfo.self],
            forKey: "UASharedPasteboardInfoItemsKey"
        ) as? [UASharedPasteboardItemInfo] else { return nil }
        self.dataSize = coder.decodeInteger(forKey: "UASharedPasteboardInfoDataSizeKey")
        self.items = items
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(nil as Any?, forKey: "UASharedPasteboardInfoDataFileKey")
        coder.encode(dataSize, forKey: "UASharedPasteboardInfoDataSizeKey")
        coder.encode(items, forKey: "UASharedPasteboardInfoItemsKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardInfoDataPathKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardInfoExtensionKey")
    }
}

@objc(UASharedPasteboardItemInfo)
final class UASharedPasteboardItemInfo: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let types: NSDictionary

    init(types: NSDictionary) {
        self.types = types
        super.init()
    }

    required init?(coder: NSCoder) {
        guard let types = coder.decodeObject(
            of: [NSDictionary.self, NSString.self, UASharedPasteboardTypeInfo.self],
            forKey: "UASharedPasteboardItemInfoTypesKey"
        ) as? NSDictionary else { return nil }
        self.types = types
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(types, forKey: "UASharedPasteboardItemInfoTypesKey")
    }
}

@objc(UASharedPasteboardTypeInfo)
final class UASharedPasteboardTypeInfo: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    let type: NSString
    let offset: NSNumber
    let size: Int

    init(type: String, offset: NSNumber, size: Int) {
        self.type = type as NSString
        self.offset = offset
        self.size = size
        super.init()
    }

    required init?(coder: NSCoder) {
        guard
            let type = coder.decodeObject(of: NSString.self, forKey: "UASharedPasteboardTypeInfoTypeKey") as? NSString,
            let offset = coder.decodeObject(of: NSNumber.self, forKey: "UASharedPasteboardTypeInfoOffsetKey") as? NSNumber
        else { return nil }
        self.type = type
        self.offset = offset
        self.size = coder.decodeInteger(forKey: "UASharedPasteboardTypeInfoSizeKey")
        super.init()
    }

    func encode(with coder: NSCoder) {
        coder.encode(type, forKey: "UASharedPasteboardTypeInfoTypeKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardTypeInfoUUIDKey")
        coder.encode(offset, forKey: "UASharedPasteboardTypeInfoOffsetKey")
        coder.encode(size, forKey: "UASharedPasteboardTypeInfoSizeKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardTypeInfoDataFileKey")
        coder.encode(nil as Any?, forKey: "UASharedPasteboardTypeInfoIndex")
    }
}

let payload = Data("native-clipboard-fixture-20261015".utf8)
let typeInfo = UASharedPasteboardTypeInfo(
    type: "public.utf8-plain-text",
    offset: NSNumber(value: 0),
    size: payload.count
)
let itemInfo = UASharedPasteboardItemInfo(
    types: ["public.utf8-plain-text" as NSString: typeInfo] as NSDictionary
)
let pasteboardInfo = UASharedPasteboardInfo(dataSize: payload.count, items: [itemInfo])
let wrapper = UASharedPasteboardInfoWrapper(
    pbInfo: pasteboardInfo,
    extraData: payload,
    extraDataType: 1,
    protocolVersion: 1
)

guard CommandLine.arguments.count == 2 else {
    fatalError("usage: archive_fixture.swift OUTPUT.bplist")
}
let outputURL = URL(fileURLWithPath: CommandLine.arguments[1])
guard outputURL.pathExtension == "bplist" else {
    fatalError("output path must end in .bplist")
}

let archiver = NSKeyedArchiver(requiringSecureCoding: true)
archiver.outputFormat = .binary
archiver.encode(wrapper, forKey: NSKeyedArchiveRootObjectKey)
archiver.finishEncoding()
let archive = archiver.encodedData
guard archive.starts(with: Data("bplist00".utf8)) else {
    fatalError("Foundation did not emit a binary plist archive")
}
try archive.write(to: outputURL, options: .atomic)
print("Wrote synthetic keyed archive: \(outputURL.path) (\(archive.count) bytes)")
