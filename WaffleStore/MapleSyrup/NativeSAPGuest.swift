import Foundation
import MapleSAP

/// Stage markers for the native store guest, written to a file inside the app
/// container. A hard crash inside the guest cannot be reported from inside
/// the app, so the last marker is left behind for the next launch.
enum DiagnosticsLog {
    private static let url: URL? = {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return nil }
        return documents.appendingPathComponent("diagnostics.log")
    }()

    static func append(_ line: String) {
        guard let url else { return }
        let entry = line.hasSuffix("\n") ? line : line + "\n"
        if let handle = try? FileHandle(forWritingTo: url) {
            defer { try? handle.close() }
            handle.seekToEndOfFile()
            handle.write(Data(entry.utf8))
        } else {
            try? Data(entry.utf8).write(to: url)
        }
    }

    static func contents() -> String {
        guard let url else { return "" }
        return (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }
}

// The application target defaults to MainActor. Guest calls must stay on the
// SAPSession executor, since asset loading/emulation can take minutes.
nonisolated final class NativeSAPGuest: AppleSAPGuest {
    let executionMode = SAPExecutionMode.interpreted
    private var handle: UInt64 = 0
    private let cache: URL
    init() throws {
        cache = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask,
                                             appropriateFor: nil, create: true).appendingPathComponent("MapleSAP", isDirectory: true)
        try FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
    }
    func initialize(hardwareID: Data) throws {
        guard handle == 0 else { throw SAPError.invalidState }
        DiagnosticsLog.append("[!] store guest: opening the Apple StoreAgent emulator")
        let status = cache.path.withCString { path in
            hardwareID.withUnsafeBytes { bytes in
                WaffleSAPOpen(UnsafeMutablePointer(mutating: path),
                              UnsafeMutablePointer(mutating: bytes.bindMemory(to: UInt8.self).baseAddress),
                              hardwareID.count, &handle)
            }
        }
        DiagnosticsLog.append("[!] store guest: open finished with status \(status)")
        guard status == 0 else { throw SAPError.nativeRuntime(Int32(status)) }
    }
    func exchange(version: UInt32, hardwareID: Data, input: Data) throws -> (output: Data, state: Int32) {
        guard handle != 0 else { throw SAPError.invalidState }
        var output: UnsafeMutablePointer<UInt8>?
        var length = 0
        var state: Int32 = -1
        let status = input.withUnsafeBytes { bytes in
            WaffleSAPExchange(handle, version, UnsafeMutablePointer(mutating: bytes.bindMemory(to: UInt8.self).baseAddress),
                              input.count, &output, &length, &state)
        }
        defer { WaffleSAPFree(output, length) }
        guard status == 0 else { throw SAPError.nativeRuntime(Int32(status)) }
        guard length <= 16 << 20 else { throw SAPError.invalidExchange }
        return (output.map { Data(bytes: $0, count: length) } ?? Data(), state)
    }
    func sign(body: Data) throws -> Data {
        guard handle != 0 else { throw SAPError.invalidState }
        var output: UnsafeMutablePointer<UInt8>?
        var length = 0
        let status = body.withUnsafeBytes { bytes in
            WaffleSAPSign(handle, UnsafeMutablePointer(mutating: bytes.bindMemory(to: UInt8.self).baseAddress),
                          body.count, &output, &length)
        }
        defer { WaffleSAPFree(output, length) }
        guard status == 0 else { throw SAPError.nativeRuntime(Int32(status)) }
        guard let output = output, length > 0, length <= 16 << 20 else { throw SAPError.emptySignature }
        return Data(bytes: output, count: length)
    }
    func close() {
        if handle != 0 { WaffleSAPClose(handle); handle = 0 }
    }
    deinit { close() }
}
