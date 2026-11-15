// Device attestation for Apple's sign-in.
//
// The proof is produced by a remote anisette server, so the app never runs a
// local FairPlay runtime and therefore needs no JIT entitlement. Which client
// identity Apple is told about matters: Apple's GSA refuses a proof made with
// the Android ADI library (-80046), and a Mac older than macOS 10.13 is
// refused too (-23782). The server advertises what it runs, and the rules
// below pick the identity Apple's gateway accepts today.
import Foundation
import CryptoKit
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct AnisetteIdentity: Codable, Equatable, Sendable {
    /// Sixteen byte machine identifier. One identity per ADI library: Apple's
    /// Android and Windows libraries each refuse the other's proof.
    public var identifier: Data
    /// The server side proof blob. Seeded locally and replaced by the server
    /// when it provisions the identity.
    public var proof: Data?

    public init(identifier: Data, proof: Data? = nil) {
        self.identifier = identifier
        self.proof = proof
    }

    public static func seeded(family: UInt8) -> AnisetteIdentity {
        AnisetteIdentity(identifier: Data(repeating: family, count: 16), proof: Data([family, 1, 2, 3]))
    }

    public var deviceID: String { UUID(uuid: identifier).uuidString }

    public var localUserID: String {
        SHA256.hash(data: identifier).map { String(format: "%02x", $0) }.joined()
    }
}

public struct AnisetteProof: Sendable {
    public let machineID: String
    public let oneTimePassword: String
    public let routingInfo: String
    public let deviceID: String
    public let clientInfo: String
    public let userAgent: String
    public let identity: AnisetteIdentity
}

public enum AnisetteError: Error, LocalizedError, Equatable {
    case refused(String)
    case unavailable(String)
    case invalidResponse(String)
    case notProvisioned(String)

    public var errorDescription: String? {
        switch self {
        case .refused(let detail): return "This device attestation server cannot sign in to Apple (\(detail))."
        case .unavailable(let host): return "The device attestation server \(host) did not answer."
        case .invalidResponse(let detail): return "The device attestation server answered unexpectedly: \(detail)"
        case .notProvisioned(let detail): return "The device attestation server has not provisioned this device: \(detail)"
        }
    }
}

public struct AppleAnisette {
    /// What GrandSlam is told the client is when the server hands out a stock
    /// or Android identity. The Windows PC gets through on those servers.
    public static let windowsClientInfo = "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKit/1 (com.apple.iTunes/12.12.4.1)>"
    public static let windowsUserAgent = "akd/1.0 CFNetwork/808.1.4"
    /// What GrandSlam is told the client is on a macOS ADI server that names an
    /// older Mac: a current Mac, with the matching user agent.
    public static let macClientInfo = "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    public static let macUserAgent = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)"

    /// Servers that hand out a stock identity, and every server on the Android
    /// ADI library: Apple refuses the developer token from those.
    private static let stockClients = [
        "<MacBookPro13,2> <macOS;13.1;22C65>",
        "<MacBookPro15,1> <Mac OS X;10.15.2;19C57>"
    ]

    /// The identity to tell GrandSlam, given what the server hands out.
    public static func selection(for advertised: String, userAgent: String) -> (clientInfo: String, userAgent: String, family: UInt8) {
        let client = advertised.trimmingCharacters(in: .whitespacesAndNewlines)
        if client.isEmpty || stockClients.contains(where: { client.hasPrefix($0) }) || client.contains("<Android;") {
            return (windowsClientInfo, windowsUserAgent, UInt8(ascii: "W"))
        }
        if let version = macVersion(client), version.0 < 10 || (version.0 == 10 && version.1 < 13) {
            return (macClientInfo, macUserAgent, UInt8(ascii: "M"))
        }
        let agent = userAgent.trimmingCharacters(in: .whitespacesAndNewlines)
        return (client, agent.isEmpty ? windowsUserAgent : agent, UInt8(ascii: "W"))
    }

    private static func macVersion(_ client: String) -> (Int, Int)? {
        for marker in ["<macOS;", "<Mac OS X;"] {
            guard let range = client.range(of: marker) else { continue }
            let rest = client[range.upperBound...]
            let version = rest.split(whereSeparator: { $0 == ";" || $0 == ">" }).first.map(String.init) ?? ""
            let parts = version.split(separator: ".").compactMap { Int($0) }
            guard let major = parts.first else { return nil }
            return (major, parts.count > 1 ? parts[1] : 0)
        }
        return nil
    }

    /// Ask a server for a machine validation proof.
    public static func proof(server: URL, identity: AnisetteIdentity?,
                              session: URLSession = .shared) async throws -> AnisetteProof {
        let advertised = try await clientInfo(server: server, session: session)
        let chosen = selection(for: advertised.clientInfo, userAgent: advertised.userAgent)
        let identity = identity ?? AnisetteIdentity.seeded(family: chosen.family)
        let payload: [String: String] = [
            "identifier": identity.identifier.base64EncodedString(),
            "adi_pb": (identity.proof ?? Data([chosen.family, 1, 2, 3])).base64EncodedString()
        ]
        let body = try JSONSerialization.data(withJSONObject: payload)
        var request = URLRequest(url: server.appendingPathComponent("v3/get_headers"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AnisetteError.invalidResponse("no response") }
        guard (200..<300).contains(http.statusCode) else {
            let detail = String(data: data, encoding: .utf8) ?? "HTTP \(http.statusCode)"
            if detail.contains("-45061") { throw AnisetteError.notProvisioned(detail) }
            throw AnisetteError.unavailable("\(server.host ?? server.absoluteString) (\(http.statusCode))")
        }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw AnisetteError.invalidResponse("not JSON")
        }
        if let message = root["message"] as? String, message.contains("-45061") {
            throw AnisetteError.notProvisioned(message)
        }
        guard let headers = root["headers"] as? [String: Any],
              let machineID = headers["machine_id"] as? String,
              let oneTimePassword = headers["one_time_password"] as? String else {
            throw AnisetteError.invalidResponse("no proof in the answer")
        }
        return AnisetteProof(machineID: machineID, oneTimePassword: oneTimePassword,
                             routingInfo: headers["routing_info"] as? String ?? "0",
                             deviceID: identity.deviceID, clientInfo: chosen.clientInfo,
                             userAgent: chosen.userAgent, identity: identity)
    }

    private static func clientInfo(server: URL, session: URLSession) async throws -> (clientInfo: String, userAgent: String) {
        var request = URLRequest(url: server.appendingPathComponent("v3/client_info"))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 30
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw AnisetteError.invalidResponse("no response") }
        guard (200..<300).contains(http.statusCode) else {
            throw AnisetteError.unavailable("\(server.host ?? server.absoluteString) (\(http.statusCode))")
        }
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let client = root["client_info"] as? String else {
            throw AnisetteError.invalidResponse("no client info")
        }
        return (client, root["user_agent"] as? String ?? "")
    }

    /// The headers Apple expects next to the signed sign-in request.
    public static func appleHeaders(_ proof: AnisetteProof, amdStyle: Bool) -> [String: String] {
        var headers: [String: String] = [
            "X-Mme-Device-Id": proof.deviceID,
            "X-Mme-Client-Info": proof.clientInfo,
            "X-Apple-I-Client-Time": ISO8601DateFormatter().string(from: Date()),
            "X-Apple-I-TimeZone": TimeZone.current.identifier,
            "X-Apple-Locale": Locale.current.identifier.replacingOccurrences(of: "_", with: "_")
        ]
        // Apple's gateway accepts the proof under either name. The AMD form is
        // what the store client sends; the I-MD form is what the attestation
        // server produces.
        if amdStyle {
            headers["X-Apple-AMD"] = proof.oneTimePassword
            headers["X-Apple-AMD-M"] = proof.machineID
        } else {
            headers["X-Apple-I-MD"] = proof.oneTimePassword
            headers["X-Apple-I-MD-M"] = proof.machineID
        }
        return headers
    }
}
