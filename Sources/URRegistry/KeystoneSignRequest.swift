//
//  File.swift
//  
//
//  Created by Zhiying Fan on 4/9/2022.
//

import Foundation

public struct KeystoneSignRequest {
    public typealias HexString = String
    
    public enum SignType: Int {
        case transaction = 1
        case typedData
        case personalMessage
        case typedTransaction
    }
    
    public var requestId: HexString
    public var signData: HexString
    public var signType: SignType
    public var chainId: UInt32
    public var path: String
    public var xfp: UInt32
    public var address: HexString
    public var origin: String
}
