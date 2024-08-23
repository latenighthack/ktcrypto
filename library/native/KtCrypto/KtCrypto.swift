import CryptoKit
import Foundation

import Foundation
import CryptoKit

@objc(KtCrypto)
public class KtCrypto: NSObject {

    @objc(ecdh:withPublicKey:) public func ecdh(privateKeyRaw: NSData, publicKeyRaw: NSData) -> NSData {
        let privateKey = try! P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyRaw as Data)
        let publicKey = try! P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyRaw as Data)
        let sharedSecret = try! privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        return sharedSecretData as NSData
    }

    @objc(sign:message:) public func sign(privateKeyRaw: NSData, message: NSData) -> NSData {
        let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: privateKeyRaw as Data)
        let signature = try! privateKey.signature(for: message as Data)
        return signature.rawRepresentation as NSData
    }

    @objc(verify:message:signature:) public func verify(publicKeyRaw: NSData, message: NSData, signature: NSData) -> Bool {
        let publicKey = try! P256.Signing.PublicKey(rawRepresentation: publicKeyRaw as Data)
        let signature = try! P256.Signing.ECDSASignature(rawRepresentation: signature as Data)
        return publicKey.isValidSignature(signature, for: message as Data)
    }

    @objc(generateKeyPair) public func generateKeyPair() -> [String: NSData] {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        return [
            "privateKey": privateKey.rawRepresentation as NSData,
            "publicKey": publicKey.rawRepresentation as NSData
        ]
    }

    @objc(fromPrivateKey:) public func fromPrivateKey(raw: NSData) -> [String: NSData]? {
        guard let privateKey = try? P256.Signing.PrivateKey(rawRepresentation: raw as Data) else {
            return nil
        }
        let publicKey = privateKey.publicKey
        return [
            "privateKey": privateKey.rawRepresentation as NSData,
            "publicKey": publicKey.rawRepresentation as NSData
        ]
    }

    @objc(encodePublicKey:) public func encodePublicKey(publicKeyRaw: NSData) -> NSData {
        let publicKey = try! P256.Signing.PublicKey(rawRepresentation: publicKeyRaw as Data)
        return publicKey.compactRepresentation as! NSData
    }

    @objc(encodePrivateKey:) public func encodePrivateKey(privateKeyRaw: NSData) -> NSData {
        let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: privateKeyRaw as Data)
        return privateKey.rawRepresentation as NSData
    }

    @objc(decodePublicKey:) public func decodePublicKey(_ encodedKey: NSData) -> NSData {
        let publicKey = try! P256.Signing.PublicKey(compactRepresentation: encodedKey as Data)
        return publicKey.rawRepresentation as NSData
    }

    @objc public func fromRawPrivateKey(_ raw: NSData) -> NSData {
        let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: raw as Data)
        return privateKey.rawRepresentation as NSData
    }
}
