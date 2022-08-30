import XCTest
@testable import URRegistry

final class URRegistryTests: XCTestCase {
    func testGetHDKey() {
        let ur = "UR:CRYPTO-HDKEY/PTAOWKAXHDCLAXDLGHLBTLDARPTPFNSASSGWMUNSSEFWHEOYWLLGMSTDJEAEYTVOTIGAGMMUFNGYDEAAHDCXRHDNCHQDMUHSDLSPWLFEVWSKETMWESSGBNBKDESRATJZAMBDBZSRYTYNGMFTNTCFAHTAADEHOEADCSFNAOAEAMTAADDYOTADLNCSDWYKCSFNYKAEYKAOCYGMAEJTNBAXAXATTAADDYOEADLRAEWKLAWKAXAEAYCYWDBZJZTYASISGRIHKKJKJYJLJTIHBKJOHSIAIAJLKPJTJYDMJKJYHSJTIEHSJPIEEOSPLADY"
        let expectedResult = CryptoHDKey(
            key: "032f547fd525b6d83cc2c44f939cc1425fa1e98d97d26b00f9e2d04952933c5128",
            chainCode: "b92b17b393612fc8e945e5c5389439ca0c0a28c3076c060b15c3f9f6523a9d19"
        )
        
        let sut = URRegistry.shared
        
        let result = sut.getHDKey(from: ur)
        
        XCTAssertEqual(result, expectedResult)
    }
    
    func testGetUncompressedKeyFromEvenY() {
        let compressedKey = "02fef03a2bd3de113f1dc1cdb1e69aa4d935dc3458d542d796f5827abbb1a58b5e"
        let uncompressedKey = "04fef03a2bd3de113f1dc1cdb1e69aa4d935dc3458d542d796f5827abbb1a58b5ebdffecfa6587da3216d50114700e5e314650cc2268e9fcb6ac31593bcc71d178"
        
        let sut = URRegistry.shared
        
        let result = sut.getUncompressedKey(from: compressedKey)
        
        XCTAssertEqual(result, uncompressedKey)
    }
    
    func testGetUncompressedKeyFromOddY() {
        let compressedKey = "03b7db1c60fed9f333a5afb0f945c4fafc7739775bc4bda24ac6979362eca0f1f2"
        let uncompressedKey = "04b7db1c60fed9f333a5afb0f945c4fafc7739775bc4bda24ac6979362eca0f1f2ae4a073a1eb2f8bad6ddb7bcee0c475456d0c490eec0913c7bc30826fff3193d"
        
        let sut = URRegistry.shared
        
        let result = sut.getUncompressedKey(from: compressedKey)
        
        XCTAssertEqual(result, uncompressedKey)
    }
}
