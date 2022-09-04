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
    
    public func getHDKey(from ur: String) -> CryptoHDKey? {
        let decoderPointer = UnsafeMutableRawPointer(mutating: decoderPtr)
        let urPointer = UnsafeMutableRawPointer(mutating: (ur as NSString).utf8String)
        let targetPointer = UnsafeMutableRawPointer(mutating: ("crypto-hdkey" as NSString).utf8String)
        
        URRegistryFFI.ur_decoder_receive(decoderPointer, urPointer)
        
        let isCompleted = URRegistryFFI.ur_decoder_is_complete(decoderPointer).pointee.value._boolean
        
        guard isCompleted else { return nil }
        
        let hdKeyPtr = URRegistryFFI.ur_decoder_resolve(decoderPointer, targetPointer).pointee.value._object
        let hdKeyPointer = UnsafeMutableRawPointer(mutating: hdKeyPtr)
                    
        let keyPtr = URRegistryFFI.crypto_hd_key_get_key_data(hdKeyPointer).pointee.value._string
        let chainCodePtr = URRegistryFFI.crypto_hd_key_get_chain_code(hdKeyPointer).pointee.value._string
        let sourceFingerprintPtr = URRegistryFFI.crypto_hd_key_get_source_fingerprint(hdKeyPointer).pointee.value._string
        
        guard
            let keyPtr = keyPtr,
            let chainCodePtr = chainCodePtr,
            let sourceFingerprintPtr = sourceFingerprintPtr
        else { return nil }
        
        let key = String(cString: keyPtr)
        let chainCode = String(cString: chainCodePtr)
        let sourceFingerprint = String(cString: sourceFingerprintPtr)
        
        return CryptoHDKey(key: key, chainCode: chainCode, sourceFingerprint: sourceFingerprint)
    }
    
    public func getUncompressedKey(from compressedKey: String) -> String? {
        let keyPointer = UnsafeMutableRawPointer(mutating: (compressedKey as NSString).utf8String)
        let keyPtr = URRegistryFFI.crypto_hd_key_get_uncompressed_key_data(keyPointer).pointee.value._string
        
        guard let keyPtr = keyPtr else { return nil }
        return String(cString: keyPtr)
    }
}
