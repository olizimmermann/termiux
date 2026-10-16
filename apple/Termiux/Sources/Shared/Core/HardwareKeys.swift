import CryptoKit
import Foundation
import LocalAuthentication
import Security
import TermiuxCore

/// Hardware-bound keys: Secure Enclave (Touch ID) and PIV smartcards such as a YubiKey's
/// PIV applet via CryptoTokenKit. Private keys never leave the hardware; the core only
/// sees public keys and asks this type to sign.
final class HardwareKeys: PlatformKeys, @unchecked Sendable {
    private let secrets: KeychainSecretStore

    init(secrets: KeychainSecretStore) {
        self.secrets = secrets
    }

    // MARK: Secure Enclave

    static var secureEnclaveAvailable: Bool { SecureEnclave.isAvailable }

    /// Creates a P-256 key in the Secure Enclave that needs Touch ID (or the login password)
    /// for every signature. Returns (tag, OpenSSH public key).
    func createSecureEnclaveKey(label: String, requireUserPresence: Bool = true) throws -> (tag: String, publicKey: String) {
        var error: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = requireUserPresence ? [.privateKeyUsage, .userPresence] : [.privateKeyUsage]
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
        else { throw error!.takeRetainedValue() as Error }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let tag = UUID().uuidString
        // dataRepresentation is an encrypted handle only this Mac's Secure Enclave can use.
        try secrets.set(id: Self.enclaveSecretID(tag), value: key.dataRepresentation)
        let publicKey = try opensshPublicKey(raw: key.publicKey.x963Representation, comment: label)
        return (tag, publicKey)
    }

    func deleteSecureEnclaveKey(tag: String) {
        try? secrets.delete(id: Self.enclaveSecretID(tag))
    }

    private static func enclaveSecretID(_ tag: String) -> String { "secure-enclave.\(tag)" }

    // MARK: PIV smartcards

    struct SmartcardKey: Identifiable, Hashable {
        let tokenID: String
        /// Application label (hex) identifying the key on the token.
        let slot: String
        let label: String
        let publicKey: String
        var id: String { tokenID + "/" + slot }
    }

    /// Private keys on inserted smartcards that can sign (EC P-256/P-384 or RSA).
    func smartcardKeys() -> [SmartcardKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
            let items = result as? [[String: Any]]
        else { return [] }
        return items.compactMap { item in
            guard let tokenID = item[kSecAttrTokenID as String] as? String,
                let appLabel = item[kSecAttrApplicationLabel as String] as? Data,
                let ref = item[kSecValueRef as String],
                CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID()
            else { return nil }
            let key = ref as! SecKey
            guard let pub = SecKeyCopyPublicKey(key),
                let raw = SecKeyCopyExternalRepresentation(pub, nil) as Data?
            else { return nil }
            let label = item[kSecAttrLabel as String] as? String ?? "Smartcard key"
            guard let line = try? opensshPublicKey(raw: raw, comment: label) else { return nil }
            return SmartcardKey(tokenID: tokenID, slot: appLabel.hexString, label: label, publicKey: line)
        }
    }

    private func smartcardKey(tokenID: String, slot: String) throws -> SecKey {
        guard let appLabel = Data(hexString: slot) else { throw PlatformSignError.Failed(message: "bad key reference") }
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
            kSecAttrTokenID as String: tokenID,
            kSecAttrApplicationLabel as String: appLabel,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let result,
            CFGetTypeID(result) == SecKeyGetTypeID()
        else {
            throw PlatformSignError.Failed(message: "Smartcard not found. Insert it and try again.")
        }
        return result as! SecKey
    }

    // MARK: PlatformKeys

    func sign(key: PlatformKeyRef, data: Data) throws -> Data {
        switch key {
        case .secureEnclave(let tag):
            guard let handle = try secrets.get(id: Self.enclaveSecretID(tag)) else {
                throw PlatformSignError.Failed(message: "This Secure Enclave key belongs to another Mac.")
            }
            let context = LAContext()
            context.localizedReason = "sign in to an SSH server"
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: handle, authenticationContext: context)
            return try privateKey.signature(for: data).derRepresentation
        case .piv(let tokenID, let slot):
            let key = try smartcardKey(tokenID: tokenID, slot: slot)
            let algorithm = Self.signatureAlgorithm(for: key)
            var error: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(key, algorithm, data as CFData, &error) as Data? else {
                let message = (error?.takeRetainedValue() as Error?)?.localizedDescription ?? "signing failed"
                throw PlatformSignError.Failed(message: message)
            }
            return signature
        }
    }

    /// SSH hashes: ECDSA uses the curve's hash (P-256 → SHA-256, P-384 → SHA-384);
    /// RSA uses rsa-sha2-512.
    private static func signatureAlgorithm(for key: SecKey) -> SecKeyAlgorithm {
        let attributes = SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
        let type = attributes[kSecAttrKeyType as String] as? String
        if type == (kSecAttrKeyTypeRSA as String) { return .rsaSignatureMessagePKCS1v15SHA512 }
        let bits = attributes[kSecAttrKeySizeInBits as String] as? Int ?? 256
        return bits > 256 ? .ecdsaSignatureMessageX962SHA384 : .ecdsaSignatureMessageX962SHA256
    }
}

extension Data {
    var hexString: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var index = hexString.startIndex
        while index < hexString.endIndex {
            let next = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}
