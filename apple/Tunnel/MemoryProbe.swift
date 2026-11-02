import Foundation
import OSLog

/// Logs the extension's memory footprint at start and every 30 s, with the headroom iOS leaves
/// before it ends the extension, at `notice` so that it survives in the system log.
final class MemoryProbe {
    private let log = Logger(subsystem: Shared.subsystem, category: "memory")
    private let queue = DispatchQueue(label: "net.vardevall.memory")
    private var timer: DispatchSourceTimer?
    private var peak: UInt64 = 0

    func start() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: 30)
        timer.setEventHandler { [weak self] in self?.report() }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    private func report() {
        guard let now = Self.footprint() else { return }
        peak = max(peak, now)
        var line = "footprint \(Self.megabytes(now)) MB, peak \(Self.megabytes(peak)) MB"
        #if os(iOS)
        line += ", headroom \(Self.megabytes(UInt64(os_proc_available_memory()))) MB"
        #endif
        log.notice("\(line, privacy: .public)")
    }

    private static func megabytes(_ bytes: UInt64) -> String {
        String(format: "%.1f", Double(bytes) / 1_048_576)
    }

    /// `phys_footprint`, which is what the system compares with the extension's limit.
    private static func footprint() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let status = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return status == KERN_SUCCESS ? info.phys_footprint : nil
    }
}
