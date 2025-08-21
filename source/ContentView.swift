//
//  ContentView.swift
//  exhale-EDR - the xprotect gui.  you can relax.
//
//  Created by Eric Chadbourne on 8/14/25.
//  chadbourne.consulting
//

import SwiftUI
import OSLog
import UniformTypeIdentifiers

struct ContentView: View {
    @State private var selectedCategory: SecurityCategory = .gatekeeper
    @State private var timeRange: TimeRange = .oneHour
    @State private var logs: [OSLogEntryLog] = []
    @State private var isLoading = false
    @State private var errorMessage: String?
    @State private var exportInProgress = false
    @State private var showExportSuccess = false

    var body: some View {
        NavigationView {
            VStack {
                HStack {
                    Picker("Category", selection: $selectedCategory) {
                        ForEach(SecurityCategory.allCases, id: \.self) { category in
                            Text(category.rawValue).tag(category)
                        }
                    }
                    .pickerStyle(.segmented)
                    
                    Picker("Time Range", selection: $timeRange) {
                        ForEach(TimeRange.allCases, id: \.self) { range in
                            Text(range.label).tag(range)
                        }
                    }
                    .frame(width: 160)
                }
                .padding()

                HStack {
                    Spacer()
                    Button {
                        exportLogs()
                    } label: {
                        Label("Export Logs", systemImage: "square.and.arrow.up")
                    }
                    .disabled(logs.isEmpty || exportInProgress)
                    .padding(.horizontal)
                }

                if isLoading {
                    ProgressView("Loading logs…")
                        .padding()
                } else if let error = errorMessage {
                    Text("Error: \(error)")
                        .foregroundColor(.red)
                        .padding()
                } else {
                    List(logs, id: \.self) { entry in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.composedMessage)
                                .font(.body)
                            Text(entry.date.formatted(date: .abbreviated, time: .standard))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .navigationTitle("Security Logs")
            .onAppear {
                loadLogs()
            }
            .onChange(of: selectedCategory) {
                loadLogs()
            }
            .onChange(of: timeRange) {
                loadLogs()
            }
            .alert("Export Complete", isPresented: $showExportSuccess) {
                Button("OK", role: .cancel) { }
            } message: {
                Text("Logs have been saved to your chosen location.")
            }
        }
    }

    private func loadLogs() {
        isLoading = true
        errorMessage = nil
        logs.removeAll()

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let entries = try recentSecurityLogs(
                    category: selectedCategory,
                    minutesBack: timeRange.minutes
                )
                DispatchQueue.main.async {
                    self.logs = entries
                    self.isLoading = false
                }
            } catch {
                DispatchQueue.main.async {
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }

    private func exportLogs() {
        guard !logs.isEmpty else { return }
        exportInProgress = true

        let text = logs.map { entry in
            "[\(entry.date.formatted(date: .abbreviated, time: .standard))] \(entry.composedMessage)"
        }.joined(separator: "\n")

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.plainText]
        panel.nameFieldStringValue = "\(selectedCategory.rawValue)-logs.txt"

        panel.begin { response in
            if response == .OK, let url = panel.url {
                do {
                    try text.write(to: url, atomically: true, encoding: .utf8)
                    showExportSuccess = true
                } catch {
                    errorMessage = "Failed to save logs: \(error.localizedDescription)"
                }
            }
            exportInProgress = false
        }
    }
}

enum SecurityCategory: String, CaseIterable {
    case gatekeeper = "Gatekeeper"
    case xprotect = "XProtect"
    case tcc = "TCC"
}

enum TimeRange: CaseIterable {
    case fifteenMinutes, oneHour, sixHours, twelveHours, twentyFourHours

    var label: String {
        switch self {
        case .fifteenMinutes: return "15 min"
        case .oneHour: return "1 hr"
        case .sixHours: return "6 hr"
        case .twelveHours: return "12 hr"
        case .twentyFourHours: return "24 hr"
        }
    }

    var minutes: Int {
        switch self {
        case .fifteenMinutes: return 15
        case .oneHour: return 60
        case .sixHours: return 360
        case .twelveHours: return 720
        case .twentyFourHours: return 1440
        }
    }
}

func recentSecurityLogs(category: SecurityCategory, minutesBack: Int) throws -> [OSLogEntryLog] {
    let store = try OSLogStore(scope: .system)
    let since = store.position(date: Date().addingTimeInterval(Double(-60 * minutesBack)))

    let predicate: NSPredicate
    switch category {
    case .gatekeeper:
        predicate = NSPredicate(format:
            "subsystem CONTAINS[c] %@ OR composedMessage CONTAINS[c] %@",
            "com.apple.security", "Gatekeeper")
    case .xprotect:
        predicate = NSPredicate(format:
            "subsystem CONTAINS[c] %@ OR composedMessage CONTAINS[c] %@",
            "com.apple.XProtect", "XProtect")
    case .tcc:
        predicate = NSPredicate(format:
            "subsystem CONTAINS[c] %@ OR composedMessage CONTAINS[c] %@",
            "com.apple.TCC", "TCC")
    }

    let entries = try store.getEntries(at: since, matching: predicate)
    return entries.compactMap { $0 as? OSLogEntryLog }
}
