import Foundation
import os.log

// MARK: - CrashSeverity

/// Severity level for a crash report, used for automated triage.
public enum CrashSeverity: String, Codable, Comparable {
    case low = "low"
    case medium = "medium"
    case high = "high"
    case critical = "critical"

    public static func < (lhs: CrashSeverity, rhs: CrashSeverity) -> Bool {
        let order: [CrashSeverity] = [.low, .medium, .high, .critical]
        return order.firstIndex(of: lhs)! < order.firstIndex(of: rhs)!
    }
}

// MARK: - CrashReport

/// A single crash report entry.
public struct CrashReport: Codable, Identifiable {
    public let id: String
    public let timestamp: Date
    public let appVersion: String
    public let osVersion: String
    public let deviceModel: String
    public let stackTrace: String
    public let exceptionType: String
    public let exceptionMessage: String
    public var severity: CrashSeverity
    public var triageNote: String?
    public var isAcknowledged: Bool

    public init(id: String = UUID().uuidString,
                timestamp: Date = Date(),
                appVersion: String,
                osVersion: String,
                deviceModel: String,
                stackTrace: String,
                exceptionType: String,
                exceptionMessage: String,
                severity: CrashSeverity = .medium,
                triageNote: String? = nil,
                isAcknowledged: Bool = false) {
        self.id = id
        self.timestamp = timestamp
        self.appVersion = appVersion
        self.osVersion = osVersion
        self.deviceModel = deviceModel
        self.stackTrace = stackTrace
        self.exceptionType = exceptionType
        self.exceptionMessage = exceptionMessage
        self.severity = severity
        self.triageNote = triageNote
        self.isAcknowledged = isAcknowledged
    }
}

// MARK: - CrashDashboardSummary

/// Dashboard summary for aggregated crash metrics.
public struct CrashDashboardSummary {
    public let totalCrashes: Int
    public let criticalCount: Int
    public let highCount: Int
    public let mediumCount: Int
    public let lowCount: Int
    public let unacknowledgedCount: Int
    public let mostFrequentException: String?
    public let lastCrashDate: Date?
}

// MARK: - CrashReportProcessor

/// Singleton service for ingesting, triaging, persisting, and summarising crash reports.
///
/// Thread-safety: mutations are dispatched onto a concurrent queue with a barrier write;
/// reads are synchronous concurrent reads on the same queue.
///
/// Storage: reports are JSON-encoded to `UserDefaults` (keyed by `storageKey`), capped at
/// `maxStoredReports` entries (newest kept). For production use this would be replaced by
/// a backend upload; the UserDefaults store acts as a local ring-buffer for offline triage.
public final class CrashReportProcessor {

    // MARK: Shared instance

    public static let shared = CrashReportProcessor()

    // MARK: Private state

    private let logger = Logger(subsystem: "com.ethosprotocol", category: "CrashReportProcessor")
    private var reports: [CrashReport] = []
    private let queue = DispatchQueue(label: "com.ethosprotocol.CrashReportProcessor",
                                      attributes: .concurrent)
    private let storageKey = "com.ethosprotocol.crash_reports"
    private let maxStoredReports = 200

    // MARK: Initialiser

    private init() {
        // Load any previously persisted reports without holding the concurrent queue
        // (the queue hasn't been used yet, so there's no race here).
        reports = Self.loadStoredReports(key: "com.ethosprotocol.crash_reports",
                                         maxCount: 200)
    }

    // MARK: - Public API

    /// Ingest a pre-built `CrashReport`, persist it, and alert if critical.
    public func ingest(_ report: CrashReport) {
        queue.async(flags: .barrier) { [self] in
            reports.append(report)
            // Keep only the newest `maxStoredReports` entries.
            if reports.count > maxStoredReports {
                reports = Array(reports.suffix(maxStoredReports))
            }
            persist()
            logger.info("CrashReportProcessor: ingested report id=\(report.id, privacy: .public) severity=\(report.severity.rawValue, privacy: .public)")
            if report.severity >= .critical {
                alertIfCritical(report)
            }
        }
    }

    /// Convenience entry point for raw uncaught-exception data. Determines severity
    /// automatically via `triageSeverity` and calls `ingest(_:)`.
    public func ingestUncaughtException(name: String,
                                         reason: String,
                                         stackTrace: String) {
        let severity = triageSeverity(exceptionType: name, message: reason)
        let report = CrashReport(
            appVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")
                as? String ?? "unknown",
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            deviceModel: "unknown",   // UIDevice is not available in SPM package scope
            stackTrace: stackTrace,
            exceptionType: name,
            exceptionMessage: reason,
            severity: severity
        )
        ingest(report)
    }

    /// Classify an exception type + message into a `CrashSeverity`.
    ///
    /// Rules (evaluated in order, first match wins):
    /// - **critical** — EXC_BAD_ACCESS, SIGSEGV, or SIGABRT in the type string
    /// - **high** — NSException in the type string *or* "fatal" anywhere in the message
    /// - **medium** — "Swift" anywhere in the type string
    /// - **low** — everything else
    public func triageSeverity(exceptionType: String, message: String) -> CrashSeverity {
        if exceptionType.contains("EXC_BAD_ACCESS")
            || exceptionType.contains("SIGSEGV")
            || exceptionType.contains("SIGABRT") {
            return .critical
        }
        if exceptionType.contains("NSException")
            || message.lowercased().contains("fatal") {
            return .high
        }
        if exceptionType.contains("Swift") {
            return .medium
        }
        return .low
    }

    /// Returns all stored reports sorted by timestamp descending (newest first).
    public func allReports() -> [CrashReport] {
        queue.sync {
            reports.sorted { $0.timestamp > $1.timestamp }
        }
    }

    /// Returns reports whose severity is at or above the supplied minimum.
    public func reports(withMinimumSeverity severity: CrashSeverity) -> [CrashReport] {
        allReports().filter { $0.severity >= severity }
    }

    /// Mark a report as acknowledged. The update is dispatched asynchronously with a
    /// barrier write; callers that need to observe the change should wait a tick.
    public func acknowledge(reportID: String) {
        queue.async(flags: .barrier) { [self] in
            guard let idx = reports.firstIndex(where: { $0.id == reportID }) else { return }
            reports[idx].isAcknowledged = true
            persist()
            logger.info("CrashReportProcessor: acknowledged report id=\(reportID, privacy: .public)")
        }
    }

    /// Aggregated metrics suitable for a crash-reporting dashboard.
    public func dashboardSummary() -> CrashDashboardSummary {
        let all = allReports()

        let criticalCount = all.filter { $0.severity == .critical }.count
        let highCount     = all.filter { $0.severity == .high     }.count
        let mediumCount   = all.filter { $0.severity == .medium   }.count
        let lowCount      = all.filter { $0.severity == .low      }.count
        let unacknowledged = all.filter { !$0.isAcknowledged }.count

        // Most frequent exception type
        var frequency: [String: Int] = [:]
        for report in all {
            frequency[report.exceptionType, default: 0] += 1
        }
        let mostFrequent = frequency.max(by: { $0.value < $1.value })?.key

        let lastCrash = all.first?.timestamp  // sorted descending, so first == newest

        return CrashDashboardSummary(
            totalCrashes: all.count,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount,
            unacknowledgedCount: unacknowledged,
            mostFrequentException: mostFrequent,
            lastCrashDate: lastCrash
        )
    }

    /// Clears all in-memory reports and removes the persisted UserDefaults entry.
    /// Intended for use in unit tests only.
    public func reset() {
        queue.sync(flags: .barrier) {
            reports = []
            UserDefaults.standard.removeObject(forKey: storageKey)
        }
    }

    // MARK: - Private helpers

    /// Log (and in production: send an alert) when a critical crash is ingested.
    private func alertIfCritical(_ report: CrashReport) {
        // In a real app this would trigger a push notification, PagerDuty alert, or email.
        // Here we log at the fault level so it surfaces prominently in Console / Instruments.
        logger.fault("""
            ‼️ CRITICAL crash ingested — id=\(report.id, privacy: .public) \
            type=\(report.exceptionType, privacy: .public) \
            message=\(report.exceptionMessage, privacy: .public)
            """)
    }

    /// JSON-encode the current reports array and write it to UserDefaults.
    /// Must be called inside a barrier block on `queue`.
    private func persist() {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(reports) else {
            logger.error("CrashReportProcessor: failed to encode reports for persistence")
            return
        }
        UserDefaults.standard.set(data, forKey: storageKey)
    }

    /// Decode the previously persisted reports from UserDefaults.
    /// Called once from `init` — no queue synchronisation needed at that point.
    private static func loadStoredReports(key: String, maxCount: Int) -> [CrashReport] {
        guard let data = UserDefaults.standard.data(forKey: key) else { return [] }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let decoded = try? decoder.decode([CrashReport].self, from: data) else {
            return []
        }
        // If the stored list somehow grew beyond the cap, trim to the newest entries.
        return Array(decoded.suffix(maxCount))
    }
}
