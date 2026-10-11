import Foundation

struct LocalAIProfile: Codable, Equatable, Identifiable {
    let id: String
    var name: String
    var baseURL: String
    var model: String

    init(id: String = UUID().uuidString, name: String, baseURL: String, model: String) {
        self.id = id
        self.name = name
        self.baseURL = baseURL
        self.model = model
    }
}

enum LocalAIProfileStore {
    private static let storageKey = "koda.localAI.profiles"

    static func load(from defaults: UserDefaults = .standard) -> [LocalAIProfile] {
        guard let data = defaults.data(forKey: storageKey),
              let profiles = try? JSONDecoder().decode([LocalAIProfile].self, from: data) else { return [] }
        return profiles
    }

    static func save(_ profiles: [LocalAIProfile], to defaults: UserDefaults = .standard) {
        guard let data = try? JSONEncoder().encode(profiles) else { return }
        defaults.set(data, forKey: storageKey)
    }

    static func migrateLegacyIfNeeded(
        baseURL: String, model: String, defaults: UserDefaults = .standard
    ) -> [LocalAIProfile] {
        let existing = load(from: defaults)
        guard existing.isEmpty, defaults.data(forKey: storageKey) == nil,
              !model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return existing }
        let profile = LocalAIProfile(name: model, baseURL: baseURL, model: model)
        save([profile], to: defaults)
        return [profile]
    }
}
