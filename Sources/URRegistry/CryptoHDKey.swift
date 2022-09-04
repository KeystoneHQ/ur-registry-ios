//
//  CryptoHDKey.swift
//  
//
//  Created by Zhiying Fan on 26/8/2022.
//

import Foundation

public struct CryptoHDKey: Equatable {
    public var key: String
    public var chainCode: String
    public var sourceFingerprint: String
}
