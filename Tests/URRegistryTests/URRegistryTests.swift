import XCTest
@testable import URRegistry

final class URRegistryTests: XCTestCase {
    func testGetHDKey() {
        let ur = "UR:CRYPTO-HDKEY/PTAOWKAXHDCLAXDLGHLBTLDARPTPFNSASSGWMUNSSEFWHEOYWLLGMSTDJEAEYTVOTIGAGMMUFNGYDEAAHDCXRHDNCHQDMUHSDLSPWLFEVWSKETMWESSGBNBKDESRATJZAMBDBZSRYTYNGMFTNTCFAHTAADEHOEADCSFNAOAEAMTAADDYOTADLNCSDWYKCSFNYKAEYKAOCYGMAEJTNBAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYWDBZJZTYASISGRIHKKJKJYJLJTIHBKJOHSIAIAJLKPJTJYDMJKJYHSJTIEHSJPIEEOSPLADY"
        let expectedResult = CryptoHDKey(
            key: "032f547fd525b6d83cc2c44f939cc1425fa1e98d97d26b00f9e2d04952933c5128",
            chainCode: "b92b17b393612fc8e945e5c5389439ca0c0a28c3076c060b15c3f9f6523a9d19",
            sourceFingerprint: 1375760032
        )
        
        let sut = URRegistry.shared
        
        let result = sut.getHDKey(from: ur)
        
        XCTAssertEqual(result, expectedResult)
    }
    
    func testGetUncompressedKeyFromEvenY() {
        let compressedKey = "02fef03a2bd3de113f1dc1cdb1e69aa4d935dc3458d542d796f5827abbb1a58b5e"
        let expectedResult = "04fef03a2bd3de113f1dc1cdb1e69aa4d935dc3458d542d796f5827abbb1a58b5ebdffecfa6587da3216d50114700e5e314650cc2268e9fcb6ac31593bcc71d178"
        
        let sut = URRegistry.shared
        
        let result = sut.getUncompressedKey(from: compressedKey)
        
        XCTAssertEqual(result, expectedResult)
    }
    
    func testGetUncompressedKeyFromOddY() {
        let compressedKey = "03b7db1c60fed9f333a5afb0f945c4fafc7739775bc4bda24ac6979362eca0f1f2"
        let expectedResult = "04b7db1c60fed9f333a5afb0f945c4fafc7739775bc4bda24ac6979362eca0f1f2ae4a073a1eb2f8bad6ddb7bcee0c475456d0c490eec0913c7bc30826fff3193d"
        
        let sut = URRegistry.shared
        
        let result = sut.getUncompressedKey(from: compressedKey)
        
        XCTAssertEqual(result, expectedResult)
    }
    
    func testNextPartUnsignedUR() {
        let signRequest = KeystoneSignRequest(
            requestId: "44313244443830392d443131312d344239352d384439372d324244423137324632363332",
            signData: "",
            signType: .typedTransaction,
            chainId: 4,
            path: "m/44'/60'/0'/0/0",
            xfp: 1375760032,
            address: "307832636539633861393136303233623031633737306535356439393165446642313734663035384335",
            origin: "gnosis safe ios"
        )
        let expectedResult1 = "UR:ETH-SIGN-REQUEST/1-1/LPADADCSLTCYGEJNWLGSHDLTOSADTPDAHDDKFYEHEYFYFYETDYESDPFYEHEHEHDPEEFWESECDPETFYESEMDPEYFWFYFWEHEMEYFGEYENEOEYAOFZAXAAAAAAAHTAADDYOEADLECSDWYKCSFNYKAEYKAEWKAEWKAOCYGMAEJTNBAMHDDRDYKSEYIAIHESIAETHSESEHENDYEYEOIDDYEHIAEMEMDYIHECECIEESESEHIHFYIYFWEHEMEEIYDYECETFXECATJLIOJTJLJKINJKCXJKHSIYIHCXINJLJKSAHPWTMK"
        let expectedResult2 = "UR:ETH-SIGN-REQUEST/2-1/LPAOADCSLTCYGEJNWLGSHDLTOSADTPDAHDDKFYEHEYFYFYETDYESDPFYEHEHEHDPEEFWESECDPETFYESEMDPEYFWFYFWEHEMEYFGEYENEOEYAOFZAXAAAAAAAHTAADDYOEADLECSDWYKCSFNYKAEYKAEWKAEWKAOCYGMAEJTNBAMHDDRDYKSEYIAIHESIAETHSESEHENDYEYEOIDDYEHIAEMEMDYIHECECIEESESEHIHFYIYFWEHEMEEIYDYECETFXECATJLIOJTJLJKINJKCXJKHSIYIHCXINJLJKIORHMTZE"
        
        let sut = URRegistry.shared
        sut.setSignRequestUREncoder(with: signRequest)
        
        let result1 = sut.nextPartUnsignedUR
        XCTAssertEqual(result1, expectedResult1)
        
        let result2 = sut.nextPartUnsignedUR
        XCTAssertEqual(result2, expectedResult2)
    }
    
    func testGetSignature() {
        let ur = "UR:ETH-SIGNATURE/OEADTPDAGDEEEODYFPEHETENESDPECFEECEHDPEEFYAOHDFPVLTNFGFHTKSPMSTOHHIHEEIHGSNLPEPLFLPMHKSOWZLSPFVOMEDWZCGTLTWTJYGTKIMYWKHLESMTGHHHZORPZEFERHURBSHDRLLUCWSOLYHTSODYGUAYCSSPBGBKGMUTCWZOQZRDGT"
        let expectedResult = "e3da463fcfc897ce5c6534654c99afae47ad59c9f283b0e2912cfd4d87f0744d7d8ff45d3996545cfbb6fe45b9df0f58b78b1bc9815ac930530818c8120a52dd1b"
        
        let sut = URRegistry.shared
        
        let result = sut.getSignature(from: ur)
        
        XCTAssertEqual(result, expectedResult)
    }
}
