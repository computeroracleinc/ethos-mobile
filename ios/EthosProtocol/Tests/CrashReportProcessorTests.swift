import XCTest
@testable import EthosProtocol

final class CrashReportProcessorTests: XCTestCase {

    private var processor: CrashReportProcessor!

    override func setUp() {
        super.setUp()
        // Wipe any state left by a previous test run so each test starts clean.
        CrashReportProcessor.shared.reset()
        processor = CrashReportProcessor.shared
    }

    override func tearDown() {
        CrashReportProcessor.shared.reset()
        super.tearDown()
    }

    // MARK: - Helpers

    private func makeReport(severity: CrashSeverity = .medium,
                             type: String = "SwiftError",
                             message: String = "test error") -> CrashReport {
        CrashReport(
            appVersion: "1.0",
            osVersion: "17.0",
            deviceModel: "iPhone15,2",
            stackTrace: "frame 0",
            exceptionType: type,
            exceptionMessage: message,
            severity: severity
        )
    }

    // MARK: - Ingest & retrieve

    func testIngestAndRetrieve() {
        let report = makeReport()
        processor.ingest(report)

        // Give the barrier write time to complete.
        waitForBarrier()

        XCTAssertEqual(processor.allReports().count, 1)
        XCTAssertEqual(processor.allReports().first?.id, report.id)
    }

    func testMultipleIngestsAreStored() {
        let r1 = makeReport(severity: .low,  type: "LowError")
        let r2 = makeReport(severity: .high, type: "NSException")
        processor.ingest(r1)
        processor.ingest(r2)

        waitForBarrier()

        XCTAssertEqual(processor.allReports().count, 2)
    }

    func testReportsAreReturnedNewestFirst() {
        let older = CrashReport(
            id: UUID().uuidString,
            timestamp: Date(timeIntervalSinceNow: -3600),
            appVersion: "1.0", osVersion: "17.0", deviceModel: "iPhone15,2",
            stackTrace: "", exceptionType: "OldError", exceptionMessage: ""
        )
        let newer = CrashReport(
            id: UUID().uuidString,
            timestamp: Date(),
            appVersion: "1.0", osVersion: "17.0", deviceModel: "iPhone15,2",
            stackTrace: "", exceptionType: "NewError", exceptionMessage: ""
        )
        processor.ingest(older)
        processor.ingest(newer)

        waitForBarrier()

        let all = processor.allReports()
        XCTAssertEqual(all.first?.exceptionType, "NewError",
                       "allReports() should return newest report first")
    }

    // MARK: - Severity triage

    func testTriageSeverityCritical_EXC_BAD_ACCESS() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "EXC_BAD_ACCESS", message: ""),
                       .critical)
    }

    func testTriageSeverityCritical_SIGSEGV() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "SIGSEGV", message: ""),
                       .critical)
    }

    func testTriageSeverityCritical_SIGABRT() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "SIGABRT", message: ""),
                       .critical)
    }

    func testTriageSeverityHigh_NSException() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "NSException", message: "some error"),
                       .high)
    }

    func testTriageSeverityHigh_FatalMessage() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "RuntimeError", message: "Fatal error: index out of range"),
                       .high)
    }

    func testTriageSeverityMedium_SwiftError() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "SwiftError", message: "something went wrong"),
                       .medium)
    }

    func testTriageSeverityLow_UnknownType() {
        XCTAssertEqual(processor.triageSeverity(exceptionType: "UnknownError", message: "minor glitch"),
                       .low)
    }

    // MARK: - Acknowledge

    func testAcknowledge() {
        let report = makeReport()
        processor.ingest(report)
        waitForBarrier()

        processor.acknowledge(reportID: report.id)
        waitForBarrier()

        XCTAssertTrue(processor.allReports().first?.isAcknowledged == true,
                      "Report should be marked acknowledged after acknowledge(reportID:)")
    }

    func testAcknowledgeUnknownIDIsNoOp() {
        let report = makeReport()
        processor.ingest(report)
        waitForBarrier()

        processor.acknowledge(reportID: "nonexistent-id")
        waitForBarrier()

        XCTAssertFalse(processor.allReports().first?.isAcknowledged == true,
                       "Acknowledging an unknown ID should not affect existing reports")
    }

    // MARK: - Dashboard summary

    func testDashboardSummary() {
        processor.ingest(makeReport(severity: .critical, type: "EXC_BAD_ACCESS"))
        processor.ingest(makeReport(severity: .critical, type: "EXC_BAD_ACCESS"))
        processor.ingest(makeReport(severity: .high,     type: "NSException"))
        waitForBarrier()

        let summary = processor.dashboardSummary()
        XCTAssertEqual(summary.totalCrashes, 3)
        XCTAssertEqual(summary.criticalCount, 2)
        XCTAssertEqual(summary.highCount, 1)
        XCTAssertEqual(summary.mediumCount, 0)
        XCTAssertEqual(summary.lowCount, 0)
        XCTAssertEqual(summary.mostFrequentException, "EXC_BAD_ACCESS")
    }

    func testDashboardSummaryEmpty() {
        let summary = processor.dashboardSummary()
        XCTAssertEqual(summary.totalCrashes, 0)
        XCTAssertNil(summary.mostFrequentException)
        XCTAssertNil(summary.lastCrashDate)
    }

    func testDashboardSummaryUnacknowledgedCount() {
        processor.ingest(makeReport(severity: .medium, type: "SwiftError"))
        processor.ingest(makeReport(severity: .high,   type: "NSException"))
        waitForBarrier()

        processor.acknowledge(reportID: processor.allReports().first!.id)
        waitForBarrier()

        let summary = processor.dashboardSummary()
        XCTAssertEqual(summary.unacknowledgedCount, 1)
    }

    func testDashboardSummaryLastCrashDate() {
        let report = makeReport()
        processor.ingest(report)
        waitForBarrier()

        let summary = processor.dashboardSummary()
        XCTAssertNotNil(summary.lastCrashDate)
    }

    // MARK: - Filter by severity

    func testFilterBySeverity() {
        processor.ingest(makeReport(severity: .low))
        processor.ingest(makeReport(severity: .critical, type: "EXC_BAD_ACCESS"))
        waitForBarrier()

        let highAndAbove = processor.reports(withMinimumSeverity: .high)
        XCTAssertEqual(highAndAbove.count, 1)
        XCTAssertEqual(highAndAbove.first?.severity, .critical)
    }

    func testFilterBySeverityReturnsAll() {
        processor.ingest(makeReport(severity: .low))
        processor.ingest(makeReport(severity: .medium))
        processor.ingest(makeReport(severity: .high, type: "NSException"))
        processor.ingest(makeReport(severity: .critical, type: "SIGSEGV"))
        waitForBarrier()

        XCTAssertEqual(processor.reports(withMinimumSeverity: .low).count, 4)
    }

    func testFilterBySeverityReturnsNone() {
        processor.ingest(makeReport(severity: .low))
        processor.ingest(makeReport(severity: .medium))
        waitForBarrier()

        XCTAssertEqual(processor.reports(withMinimumSeverity: .critical).count, 0)
    }

    // MARK: - CrashSeverity ordering

    func testSeverityComparable() {
        XCTAssertLessThan(CrashSeverity.low, .medium)
        XCTAssertLessThan(CrashSeverity.medium, .high)
        XCTAssertLessThan(CrashSeverity.high, .critical)
        XCTAssertFalse(CrashSeverity.critical < .critical)
    }

    // MARK: - Reset

    func testResetClearsAllReports() {
        processor.ingest(makeReport())
        waitForBarrier()
        XCTAssertFalse(processor.allReports().isEmpty)

        processor.reset()
        XCTAssertTrue(processor.allReports().isEmpty)
    }

    // MARK: - Private helper

    /// Spin a short expectation to let barrier writes on the internal concurrent queue settle.
    private func waitForBarrier(timeout: TimeInterval = 0.2) {
        let exp = expectation(description: "barrier")
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { exp.fulfill() }
        wait(for: [exp], timeout: timeout + 0.5)
    }
}
