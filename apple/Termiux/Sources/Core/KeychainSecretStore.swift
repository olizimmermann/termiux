import Foundation
import Security
import TermiuxCore

/// Stores core secrets (passwords, private keys) as generic passwords in the Keychain.
/// Items never leave this device (`…ThisDeviceOnly`); sync will use its own encrypted vault.
final class KeychainSecretStore: SecretStore, @unchecked Sendable {
    private let service: String

    init(service: String = Bundle.main.bundleIdentifier ?? "com.ozimmermann.termiux") {
        self.service = service
    }

    private func query(_ id: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: id,
        ]
    }

    func get(id: String) throws -> Data? {
        var q = query(id)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw SecretStoreError.Failed(message: Self.describe(status))
        }
    }

    func set(id: String, value: Data) throws {
        let update = [kSecValueData as String: value]
        var status = SecItemUpdate(query(id) as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var add = query(id)
            add[kSecValueData as String] = value
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            add[kSecAttrLabel as String] = "Termiux secret"
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw SecretStoreError.Failed(message: Self.describe(status)) }
    }

    func delete(id: String) throws {
        let status = SecItemDelete(query(id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecretStoreError.Failed(message: Self.describe(status))
        }
    }

    private static func describe(_ status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)"
    }
}
