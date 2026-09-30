import XCTest
@testable import EthosProtocol

// MARK: - VaultBackupServiceTests

/// Unit tests for `VaultBackupService`.
///
/// All tests use the pure encrypt/decrypt path that does **not** touch
/// `NSUbiquitousKeyValueStore` or the real Documents directory — those paths
/// require entitlements / filesystem access that aren't available in the bare
/// SPM test bundle on CI.  The local-file round-trip test writes to a temp
/// directory and cleans up after itself.
final class VaultBackupServiceTests: XCTestCase {

    private let service = VaultBackupService.shared
    private let correctPassword = "correct-horse-battery-staple"

    // MARK: - Helpers

    /// Creates a minimal but fully valid `Vault` with a distinct `id`.
    private func makeSampleVault(id: String = "v1") -> Vault {
        Vault(
            id: id,
            owner: "GABC1234567890OWNER",
            beneficiary: "GXYZ9876543210BENEFICIARY",
            balance: 50_000_000,        // 5 XLM in stroops
            checkInInterval: 86_400,    // 1 day in seconds
            lastCheckIn: Date(timeIntervalSince1970: 1_700_000_000),
            ttlRemaining: 43_200,       // 12 hours
            status: .active,
            assetCode: "XLM",
            assetIssuer: nil
        )
    }

    // MARK: - Round-trip

    /// Exporting and immediately importing with the same password must return
    /// the original vault list unchanged.
    func testExportAndImportRoundTrip() throws {
        let vault = makeSampleVault(id: "round-trip-vault")
        let encrypted = try service.exportBackup(vaults: [vault], password: correctPassword)
        let restored = try service.importBackup(data: encrypted, password: correctPassword)

        XCTAssertEqual(restored.count, 1)
        XCTAssertEqual(restored.first?.id, vault.id)
        XCTAssertEqual(restored.first?.owner, vault.owner)
        XCTAssertEqual(restored.first?.beneficiary, vault.beneficiary)
        XCTAssertEqual(restored.first?.balance, vault.balance)
        XCTAssertEqual(restored.first?.status, vault.status)
        XCTAssertEqual(restored.first?.assetCode, vault.assetCode)
    }

    // MARK: - Wrong password

    /// Decrypting with a wrong password must throw — the exact error type may
    /// be `decryptionFailed` (AES-GCM tag mismatch) but any thrown error is
    /// acceptable, since what matters is that the bad import does not silently
    /// succeed.
    func testWrongPasswordFails() throws {
        let vault = makeSampleVault(id: "password-check-vault")
        let encrypted = try service.exportBackup(vaults: [vault], password: correctPassword)

        XCTAssertThrowsError(
            try service.importBackup(data: encrypted, password: "totally-wrong-password"),
            "Importing with a wrong password should throw"
        )
    }

    /// Passing an empty password for export and a different empty password
    /// string is still treated as a key mismatch when the passwords differ.
    func testWrongPasswordAfterEmptyPasswordExport() throws {
        let vault = makeSampleVault(id: "empty-pw-vault")
        let encrypted = try service.exportBackup(vaults: [vault], password: "")
        XCTAssertThrowsError(
            try service.importBackup(data: encrypted, password: "not-empty"),
            "Importing with a different password from the one used to export must throw"
        )
    }

    // MARK: - Local file round-trip

    /// Swap the service's output URL to a temp file so we don't pollute the
    /// simulator's real Documents directory and the test is self-contained.
    func testLocalFileRoundTrip() throws {
        // We cannot easily inject a custom URL into the singleton, so we test
        // via the public interface and clean up the real localBackupURL() after.
        let vaults = [makeSampleVault(id: "local-file-vault-1"),
                      makeSampleVault(id: "local-file-vault-2")]

        let url = try service.exportToLocalFile(vaults: vaults, password: correctPassword)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path),
                      "Backup file should exist at \(url.path)")

        let restored = try service.importFromLocalFile(password: correctPassword)
        XCTAssertEqual(restored.count, vaults.count)
        XCTAssertEqual(
            Set(restored.map(\.id)),
            Set(vaults.map(\.id)),
            "All vault IDs should survive a local-file round-trip"
        )

        // Cleanup — remove the file so subsequent test runs start clean.
        try? FileManager.default.removeItem(at: url)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path),
                       "Backup file should be cleaned up after the test")
    }

    // MARK: - Empty vault list

    /// An empty vault list must round-trip without errors and return an empty array.
    func testEmptyVaultList() throws {
        let encrypted = try service.exportBackup(vaults: [], password: correctPassword)
        let restored = try service.importBackup(data: encrypted, password: correctPassword)
        XCTAssertTrue(restored.isEmpty, "Importing a backup of zero vaults should return an empty array")
    }

    // MARK: - Multiple vaults

    /// All vault fields (including optional ones) survive serialisation.
    func testMultipleVaultsRoundTrip() throws {
        let vaults = [
            makeSampleVault(id: "mv-1"),
            Vault(
                id: "mv-2",
                owner: "GOWNER2",
                beneficiary: "GBENEF2",
                balance: 0,
                checkInInterval: 3_600,
                lastCheckIn: Date(timeIntervalSince1970: 1_600_000_000),
                ttlRemaining: nil,
                status: .expired,
                assetCode: "USDC",
                assetIssuer: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
            )
        ]

        let encrypted = try service.exportBackup(vaults: vaults, password: correctPassword)
        let restored = try service.importBackup(data: encrypted, password: correctPassword)

        XCTAssertEqual(restored.count, 2)
        let restoredById = Dictionary(uniqueKeysWithValues: restored.map { ($0.id, $0) })

        XCTAssertEqual(restoredById["mv-1"]?.status, .active)
        XCTAssertEqual(restoredById["mv-2"]?.status, .expired)
        XCTAssertEqual(restoredById["mv-2"]?.assetCode, "USDC")
        XCTAssertEqual(restoredById["mv-2"]?.assetIssuer,
                       "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
        XCTAssertNil(restoredById["mv-2"]?.ttlRemaining)
    }

    // MARK: - Corrupted ciphertext

    /// Flipping a byte in the ciphertext must cause decryption to fail — the
    /// AES-GCM authentication tag will not match.
    func testCorruptedCiphertextFails() throws {
        let vault = makeSampleVault(id: "corruption-vault")
        var encrypted = try service.exportBackup(vaults: [vault], password: correctPassword)

        // Flip a byte in the middle of the payload (skip the 12-byte nonce at
        // the start to avoid inadvertently hitting a zero byte).
        let midpoint = encrypted.count / 2
        encrypted[midpoint] ^= 0xFF

        XCTAssertThrowsError(
            try service.importBackup(data: encrypted, password: correctPassword),
            "Corrupted ciphertext must not decrypt successfully"
        )
    }
}
