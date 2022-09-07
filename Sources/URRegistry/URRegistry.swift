//
//  URRegistry.swift
//
//
//  Created by Zhiying Fan on 26/8/2022.
//

import Foundation
import URRegistryFFI

public class URRegistry {
    public static let shared = URRegistry()
    
    private let decoderPtr = URRegistryFFI.ur_decoder_new().pointee.value._object
    
    private init() {}
    
    /// Get a CryptoHDKey instance provided by a UR
    /// - Parameter ur: An UR string
    /// - Returns: An instance of CryptoHDKey
    public func getHDKey(from ur: String) -> CryptoHDKey? {
        let decoderPointer = UnsafeMutableRawPointer(mutating: decoderPtr)
        let urPointer = UnsafeMutableRawPointer(mutating: (ur as NSString).utf8String)
        let targetPointer = UnsafeMutableRawPointer(mutating: ("crypto-hdkey" as NSString).utf8String)
        
        URRegistryFFI.ur_decoder_receive(decoderPointer, urPointer)
        
        let isCompleted = URRegistryFFI.ur_decoder_is_complete(decoderPointer).pointee.safeValue?._boolean ?? false
        
        guard isCompleted else { return nil }
        
        let hdKeyPtr = URRegistryFFI.ur_decoder_resolve(decoderPointer, targetPointer).pointee.safeValue?._object
        let hdKeyPointer = UnsafeMutableRawPointer(mutating: hdKeyPtr)
        
        let keyPtr = URRegistryFFI.crypto_hd_key_get_key_data(hdKeyPointer).pointee.safeValue?._string
        let chainCodePtr = URRegistryFFI.crypto_hd_key_get_chain_code(hdKeyPointer).pointee.safeValue?._string
        let sourceFingerprintPtr = URRegistryFFI.crypto_hd_key_get_source_fingerprint(hdKeyPointer).pointee.safeValue?._string
        
        guard
            let keyPtr = keyPtr,
            let chainCodePtr = chainCodePtr,
            let sourceFingerprintPtr = sourceFingerprintPtr,
            let sourceFingerprint = UInt32(String(cString: sourceFingerprintPtr), radix: 16)
        else { return nil }
        
        let key = String(cString: keyPtr)
        let chainCode = String(cString: chainCodePtr)
        
        return CryptoHDKey(key: key, chainCode: chainCode, sourceFingerprint: sourceFingerprint)
    }
    
    /// Uncompress public key
    /// - Parameter compressedKey: Compressed public key
    /// - Returns: The uncompressed public key
    public func getUncompressedKey(from compressedKey: String) -> String? {
        let keyPointer = UnsafeMutableRawPointer(mutating: (compressedKey as NSString).utf8String)
        let keyPtr = URRegistryFFI.crypto_hd_key_get_uncompressed_key_data(keyPointer).pointee.safeValue?._string
        
        guard let keyPtr = keyPtr else { return nil }
        return String(cString: keyPtr)
    }
        
    /// Generate a QR code value which is a UR for hardware wallet to sign
    /// - Parameter signRequest: A KeystoneSignRequest holding all of the required information
    /// - Returns: An unsigned UR
    public func requestSign(signRequest: KeystoneSignRequest) -> String? {
        let requestIdPointer = UnsafeMutableRawPointer(mutating: (signRequest.requestId as NSString).utf8String)
        let signDataPointer = UnsafeMutableRawPointer(mutating: (signRequest.signData as NSString).utf8String)
        let pathPointer = UnsafeMutableRawPointer(mutating: (signRequest.path as NSString).utf8String)
        let addressPointer = UnsafeMutableRawPointer(mutating: (signRequest.address as NSString).utf8String)
        let originPointer = UnsafeMutableRawPointer(mutating: (signRequest.origin as NSString).utf8String)
        
        let ethSignRequest = URRegistryFFI.eth_sign_request_construct(
            requestIdPointer,
            signDataPointer,
            UInt32(signRequest.signType.rawValue),
            signRequest.chainId,
            pathPointer,
            signRequest.xfp,
            addressPointer,
            originPointer
        )

        let ethSignRequestPtr = ethSignRequest?.pointee.safeValue?._object
        let ethSignRequestPointer = UnsafeMutableRawPointer(mutating: ethSignRequestPtr)
        let urEncoderPtr = URRegistryFFI.eth_sign_request_get_ur_encoder(ethSignRequestPointer).pointee.safeValue?._object
        let urEncoderPointer = UnsafeMutableRawPointer(mutating: urEncoderPtr)
        let qrValuePtr = URRegistryFFI.ur_encoder_next_part(urEncoderPointer).pointee.safeValue?._string
        
        guard let qrValuePtr = qrValuePtr else { return nil }
        
        return String(cString: qrValuePtr).uppercased()
    }
    
    /// Get signature information provided by a UR
    /// - Parameter ur: An UR string
    /// - Returns: The hex string of the signature
    public func getSignature(from ur: String) -> String? {
        let decoderPointer = UnsafeMutableRawPointer(mutating: decoderPtr)
        let urPointer = UnsafeMutableRawPointer(mutating: (ur as NSString).utf8String)
        let targetPointer = UnsafeMutableRawPointer(mutating: ("eth-signature" as NSString).utf8String)
        
        URRegistryFFI.ur_decoder_receive(decoderPointer, urPointer)
        
        let isCompleted = URRegistryFFI.ur_decoder_is_complete(decoderPointer).pointee.safeValue?._boolean ?? false
        
        guard isCompleted else { return nil }
        
        let ethSignaturePtr = URRegistryFFI.ur_decoder_resolve(decoderPointer, targetPointer).pointee.safeValue?._object
        let ethSignaturePtrPointer = UnsafeMutableRawPointer(mutating: ethSignaturePtr)
        
        let signaturePtr = URRegistryFFI.eth_signature_get_signature(ethSignaturePtrPointer).pointee.safeValue?._string
        
        guard
            let signaturePtr = signaturePtr
        else { return nil }
        
        let signature = String(cString: signaturePtr)
        
        return signature
    }
}

extension Response {
    var safeValue: Value? {
        if status_code == 0 {
            return value
        } else {
            fatalError("Error: \(String(cString: error_message))")
        }
    }
}
