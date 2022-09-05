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
    
    public init(
        requestId: HexString,
        signData: HexString,
        signType: SignType,
        chainId: UInt32,
        path: String,
        xfp: UInt32,
        address: HexString,
        origin: String
    ) {
        self.requestId = requestId
        self.signData = signData
        self.signType = signType
        self.chainId = chainId
        self.path = path
        self.xfp = xfp
        self.address = address
        self.origin = origin
    }
}
