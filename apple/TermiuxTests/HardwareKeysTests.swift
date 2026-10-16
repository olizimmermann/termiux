import CryptoKit
import Foundation
import TermiuxCore
import XCTest

@testable import Termiux

final class HardwareKeysTests: XCTestCase {
    func testSecureEnclaveSignatureVerifies() throws {
        try XCTSkipUnless(HardwareKeys.secureEnclaveAvailable, "no Secure Enclave")
        let secrets = KeychainSecretStore(service: "com.ozimmermann.termiux.tests")
        let keys = HardwareKeys(secrets: secrets)
        let (tag, publicKey) = try keys.createSecureEnclaveKey(label: "test", requireUserPresence: false)
        defer { keys.deleteSecureEnclaveKey(tag: tag) }
        XCTAssertTrue(publicKey.hasPrefix("ecdsa-sha2-nistp256 "), publicKey)
        XCTAssertTrue(publicKey.hasSuffix(" test"))

        let data = Data("ssh session data".utf8)
        let der = try keys.sign(key: .secureEnclave(tag: tag), data: data)
        let handle = try XCTUnwrap(try secrets.get(id: "secure-enclave.\(tag)"))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: handle)
        let signature = try P256.Signing.ECDSASignature(derRepresentation: der)
        XCTAssertTrue(key.publicKey.isValidSignature(signature, for: data))

        // The public key line must be the one the core derives from the same key.
        let line = try opensshPublicKey(raw: key.publicKey.x963Representation, comment: "test")
        XCTAssertEqual(line, publicKey)
    }

    func testUnknownSecureEnclaveTagFails() {
        let keys = HardwareKeys(secrets: KeychainSecretStore(service: "com.ozimmermann.termiux.tests"))
        XCTAssertThrowsError(try keys.sign(key: .secureEnclave(tag: "missing"), data: Data()))
    }

    func testHexRoundTrip() {
        let data = Data([0x00, 0xab, 0xff, 0x10])
        XCTAssertEqual(data.hexString, "00abff10")
        XCTAssertEqual(Data(hexString: "00abff10"), data)
        XCTAssertNil(Data(hexString: "abc"))
    }
}
