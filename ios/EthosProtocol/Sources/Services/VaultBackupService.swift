import Foundation
import CryptoKit
import os.log

// MARK: - VaultBackup

/// Portable, encrypted snapshot of a user's vaults for backup and restore.
/// Version-tagged so future schema changes can be decoded defensively.
struct VaultBackup: Codable {
    /// Schema version — always "1.0" for now; incremented if the serialised
    /// shape changes in a breaking way so importBackup can apply migration logic.
    var version: String = "1.0"
    /// When the backup was created (ISO-8601 encoded by the service).
    var exportedAt: Date
    /// The full set of vaults captured in this backup.
    var vaults: [Vault]
    /// SHA-256 hex digest of the JSON-encoded `vaults` array, computed before
    /// wrapping in this struct.  Verified on import so a truncated or tampered
    /// backup is caught before it overwrites live data.
    var checksum: String
}

// MARK: - VaultBackupError

enum VaultBackupError: LocalizedError {
    case encryptionFailed
    case decryptionFailed
    case invalidBackup
    case checksumMismatch
    case exportFailed
    case importFailed

    var errorDescription: String? {
        switch self {
        case .encryptionFailed:   return "Failed to encrypt vault backup."
        case .decryptionFailed:   return "Failed to decrypt vault backup. Check your password."
        case .invalidBackup:      return "The backup file is invalid or corrupted."
        case .checksumMismatch:   return "Backup integrity check failed — the file may have been tampered with."
        case .exportFailed:       return "Failed to export vault backup."
        case .importFailed:       return "Failed to import vault backup."
        }
    }
}

// MARK: - VaultBackupService

/// Handles encrypted export and import of a user's vault list.
///
/// Encryption: AES-GCM with a 256-bit key derived from the user-supplied
/// password via SHA-256.  This is a deterministic KDF — appropriate here
/// because the primary threat model is accidental exposure (e.g. an iCloud
/// drive accessible to a third party) rather than an offline brute-force
/// campaign.  For stronger security, swap `deriveKey` to use a proper PBKDF
/// (e.g. PBKDF2 / Argon2) in a future version bump.
///
/// Integrity: a SHA-256 hex checksum of the plain-text vault JSON is embedded
/// in the `VaultBackup` envelope and re-verified on import so truncated or
/// tampered backups are rejected before they touch live data.
final class VaultBackupService {

    static let shared = VaultBackupService()
    private init() {}

    private let logger = Logger(subsystem: "com.ethosprotocol", category: "VaultBackupService")
    private let backupVersion = "1.0"

    // MARK: - Core export / import

    /// Encrypts `vaults` with `password` and returns the raw ciphertext.
    ///
    /// Format: AES-GCM combined representation (nonce ‖ ciphertext ‖ tag),
    /// wrapping a JSON-encoded `VaultBackup` envelope.
    func exportBackup(vaults: [Vault], password: String) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys   // deterministic for checksum stability

        // 1. Encode the vault list and compute its integrity checksum.
        let vaultsData: Data
        do {
            vaultsData = try encoder.encode(vaults)
        } catch {
            logger.error("exportBackup: failed to encode vaults — \(error.localizedDescription)")
            throw VaultBackupError.exportFailed
        }
        let checksum = sha256Hex(vaultsData)

        // 2. Assemble the envelope.
        let backup = VaultBackup(
            version: backupVersion,
            exportedAt: Date(),
            vaults: vaults,
            checksum: checksum
        )

        let backupData: Data
        do {
            backupData = try encoder.encode(backup)
        } catch {
            logger.error("exportBackup: failed to encode VaultBackup envelope — \(error.localizedDescription)")
            throw VaultBackupError.exportFailed
        }

        // 3. Derive key and encrypt.
        let key = try deriveKey(from: password)
        do {
            let sealed = try AES.GCM.seal(backupData, using: key)
            guard let combined = sealed.combined else {
                logger.error("exportBackup: AES.GCM.seal returned nil combined data")
                throw VaultBackupError.encryptionFailed
            }
            logger.info("exportBackup: encrypted \(vaults.count) vault(s), \(combined.count) bytes")
            return combined
        } catch let backupError as VaultBackupError {
            throw backupError
        } catch {
            logger.error("exportBackup: AES-GCM encryption failed — \(error.localizedDescription)")
            throw VaultBackupError.encryptionFailed
        }
    }

    /// Decrypts `data` with `password` and returns the restored vault list.
    ///
    /// Throws `VaultBackupError.decryptionFailed` if the password is wrong or
    /// the ciphertext is corrupt, and `VaultBackupError.checksumMismatch` if
    /// the plaintext envelope's integrity digest doesn't match after decryption.
    func importBackup(data: Data, password: String) throws -> [Vault] {
        // 1. Derive key and open the sealed box.
        let key = try deriveKey(from: password)
        let plaintext: Data
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: data)
            plaintext = try AES.GCM.open(sealedBox, using: key)
        } catch {
            logger.error("importBackup: decryption failed — \(error.localizedDescription)")
            throw VaultBackupError.decryptionFailed
        }

        // 2. Decode the envelope.
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let backup: VaultBackup
        do {
            backup = try decoder.decode(VaultBackup.self, from: plaintext)
        } catch {
            logger.error("importBackup: failed to decode VaultBackup — \(error.localizedDescription)")
            throw VaultBackupError.invalidBackup
        }

        // 3. Re-encode the vault list with the same settings used during export
        //    and verify the checksum.
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
        guard let vaultsData = try? encoder.encode(backup.vaults) else {
            logger.error("importBackup: failed to re-encode vaults for checksum verification")
            throw VaultBackupError.invalidBackup
        }
        let computedChecksum = sha256Hex(vaultsData)
        guard computedChecksum == backup.checksum else {
            logger.error("importBackup: checksum mismatch — expected \(backup.checksum), got \(computedChecksum)")
            throw VaultBackupError.checksumMismatch
        }

        logger.info("importBackup: restored \(backup.vaults.count) vault(s) from backup v\(backup.version)")
        return backup.vaults
    }

    // MARK: - iCloud key-value store

    /// Exports `vaults` and stores the encrypted backup in iCloud key-value storage.
    ///
    /// iCloud KVS has a per-key 1 MB limit — adequate for a realistic vault count
    /// but enforced at the OS level; callers should catch and present any error.
    /// Proceeds even when iCloud sync is disabled (logs a warning so the user can
    /// investigate), because the KVS write itself may still succeed.
    func exportToiCloud(vaults: [Vault], password: String) throws {
        if !ICloudSyncService.shared.isSyncEnabled {
            logger.warning("exportToiCloud: iCloud sync is not enabled — writing anyway, but data may not propagate")
        }
        let encrypted = try exportBackup(vaults: vaults, password: password)
        let base64 = encrypted.base64EncodedString()
        NSUbiquitousKeyValueStore.default.set(base64, forKey: "com.ethosprotocol.vault_backup")
        NSUbiquitousKeyValueStore.default.synchronize()
        logger.info("exportToiCloud: wrote \(base64.count) base64 chars to iCloud KVS")
    }

    /// Reads the encrypted backup from iCloud key-value storage and decrypts it.
    func importFromiCloud(password: String) throws -> [Vault] {
        guard let base64 = NSUbiquitousKeyValueStore.default.string(forKey: "com.ethosprotocol.vault_backup"),
              let data = Data(base64Encoded: base64) else {
            logger.error("importFromiCloud: no backup found in iCloud KVS")
            throw VaultBackupError.importFailed
        }
        logger.info("importFromiCloud: read \(data.count) bytes from iCloud KVS")
        return try importBackup(data: data, password: password)
    }

    // MARK: - Local file

    /// Returns the URL of the on-device backup file in the user's Documents directory.
    ///
    /// The `.ebk` extension is chosen to give the file a distinct identity in Files.app
    /// and avoid confusion with generic `.json` or `.dat` exports.
    func localBackupURL() -> URL {
        FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ethos_vault_backup.ebk")
    }

    /// Exports `vaults` to `localBackupURL()` and returns the URL on success.
    func exportToLocalFile(vaults: [Vault], password: String) throws -> URL {
        let encrypted = try exportBackup(vaults: vaults, password: password)
        let url = localBackupURL()
        do {
            try encrypted.write(to: url, options: .atomic)
            logger.info("exportToLocalFile: wrote \(encrypted.count) bytes to \(url.lastPathComponent)")
        } catch {
            logger.error("exportToLocalFile: write failed — \(error.localizedDescription)")
            throw VaultBackupError.exportFailed
        }
        return url
    }

    /// Reads the backup from `localBackupURL()` and decrypts it.
    func importFromLocalFile(password: String) throws -> [Vault] {
        let url = localBackupURL()
        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            logger.error("importFromLocalFile: read failed — \(error.localizedDescription)")
            throw VaultBackupError.importFailed
        }
        logger.info("importFromLocalFile: read \(data.count) bytes from \(url.lastPathComponent)")
        return try importBackup(data: data, password: password)
    }

    // MARK: - Private helpers

    /// Returns the lowercase hex-encoded SHA-256 digest of `data`.
    private func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Derives a 256-bit `SymmetricKey` from `password` using SHA-256.
    ///
    /// This is intentionally simple — the output is as strong as the password
    /// itself.  A future version bump can replace this with PBKDF2 or Argon2
    /// and store the salt alongside the ciphertext.
    private func deriveKey(from password: String) throws -> SymmetricKey {
        guard let passwordData = password.data(using: .utf8) else {
            throw VaultBackupError.encryptionFailed
        }
        let keyData = Data(SHA256.hash(data: passwordData))
        return SymmetricKey(data: keyData)
    }
}
