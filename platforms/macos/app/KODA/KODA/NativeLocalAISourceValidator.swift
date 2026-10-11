import Dispatch
import Foundation
import JavaScriptCore

/// Syntax and conservative interface checks for AI-generated non-Python source.
/// The candidate is parsed, never executed or compiled as an application.
enum NativeLocalAISourceValidator {
    static func validate(original: String, proposed: String, fileExtension: String) async throws {
        switch fileExtension.lowercased() {
        case "xml": try validateXML(original: original, proposed: proposed)
        case "js": try await validateJavaScript(original: original, proposed: proposed)
        case "java": try await validateJava(original: original, proposed: proposed)
        default: throw NativeLocalAIFixError.unsupportedFile
        }
    }

    private static func validateXML(original: String, proposed: String) throws {
        let previous = try parseXML(original, isOriginal: true)
        let current = try parseXML(proposed, isOriginal: false)
        guard previous.root.name == current.root.name,
              previous.root.namespaces == current.root.namespaces,
              previous.elements == current.elements,
              previous.identities == current.identities else {
            throw NativeLocalAIFixError.changedSourceInterface(
                "XML 루트·네임스페이스·요소 수 또는 이름/ID 속성이 변경되었습니다")
        }
    }

    private struct XMLRoot {
        let name: String
        let namespaces: [String: String]
    }

    private struct XMLStructure {
        let root: XMLRoot
        let elements: [String: Int]
        let identities: [String: Int]
    }

    private final class XMLRootReader: NSObject, XMLParserDelegate {
        var root: XMLRoot?
        var elements: [String: Int] = [:]
        var identities: [String: Int] = [:]

        func parser(_ parser: XMLParser, didStartElement elementName: String,
                    namespaceURI: String?, qualifiedName qName: String?,
                    attributes attributeDict: [String: String]) {
            elements[elementName, default: 0] += 1
            for key in ["name", "android:name", "id", "android:id"] {
                if let value = attributeDict[key] {
                    identities["\(elementName):\(key)=\(value)", default: 0] += 1
                }
            }
            if root == nil {
                root = XMLRoot(
                    name: elementName,
                    namespaces: attributeDict.filter { $0.key == "xmlns" || $0.key.hasPrefix("xmlns:") }
                )
            }
        }

        func parser(_ parser: XMLParser, resolveExternalEntityName name: String,
                    systemID: String?) -> Data? { nil }
    }

    private static func parseXML(_ source: String, isOriginal: Bool) throws -> XMLStructure {
        // Reject DTDs entirely: XMLParser must never fetch or expand model-supplied entities.
        if source.range(of: #"<!\s*(?:DOCTYPE|ENTITY)\b"#,
                        options: [.regularExpression, .caseInsensitive]) != nil {
            throw isOriginal
                ? NativeLocalAIFixError.syntaxUnavailable("원본 XML에 DTD가 있어 안전하게 검증할 수 없습니다")
                : NativeLocalAIFixError.invalidSyntax
        }
        let parser = XMLParser(data: Data(source.utf8))
        parser.shouldResolveExternalEntities = false
        parser.externalEntityResolvingPolicy = .never
        let reader = XMLRootReader()
        parser.delegate = reader
        guard parser.parse(), let root = reader.root else {
            throw isOriginal
                ? NativeLocalAIFixError.syntaxUnavailable("원본 XML의 구문을 확인할 수 없습니다")
                : NativeLocalAIFixError.invalidSyntax
        }
        return XMLStructure(root: root, elements: reader.elements, identities: reader.identities)
    }

    private static func validateJavaScript(original: String, proposed: String) async throws {
        // JavaScriptCore parses ordinary scripts inside the sandbox without executing them.
        // Module syntax needs Node's --check parser; never evaluate untrusted source to validate it.
        if checkScriptSyntax(original) {
            guard checkScriptSyntax(proposed) else { throw NativeLocalAIFixError.invalidSyntax }
        } else {
            guard let node = ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"]
                .first(where: FileManager.default.isExecutableFile(atPath:)) else {
                throw NativeLocalAIFixError.syntaxUnavailable(
                    "이 JavaScript 파일은 ES 모듈 등 별도 문법 검사가 필요하지만 앱에서 Node.js에 접근할 수 없습니다")
            }
            let directory = try makeTemporaryDirectory()
            defer { try? FileManager.default.removeItem(at: directory) }

            let originalModes = try await parseJavaScript(original, name: "original", node: node,
                                                          directory: directory)
            guard !originalModes.isEmpty else {
                throw NativeLocalAIFixError.syntaxUnavailable("원본 JavaScript의 구문을 확인할 수 없습니다")
            }
            let candidateModes = try await parseJavaScript(proposed, name: "candidate", node: node,
                                                           directory: directory)
            guard !candidateModes.isDisjoint(with: originalModes) else {
                throw NativeLocalAIFixError.invalidSyntax
            }
        }
        let previousDeclarations = javascriptExports(original).union(javascriptNamedDeclarations(original))
        let currentDeclarations = javascriptExports(proposed).union(javascriptNamedDeclarations(proposed))
        guard previousDeclarations.isSubset(of: currentDeclarations) else {
            throw NativeLocalAIFixError.changedSourceInterface("기존 JavaScript export·함수·클래스 이름이 제거되거나 변경되었습니다")
        }
    }

    private static func javascriptNamedDeclarations(_ source: String) -> Set<String> {
        let masked = javascriptWithoutCommentsAndLiterals(source)
        let patterns = [
            #"(?m)^\s*(?:(?:export|default|async)\s+)*function\s+([A-Za-z_$][\w$]*)\s*\("#,
            #"(?m)^\s*(?:(?:export|default)\s+)*class\s+([A-Za-z_$][\w$]*)\b"#
        ]
        var names: Set<String> = []
        for pattern in patterns {
            guard let expression = try? NSRegularExpression(pattern: pattern) else { continue }
            for match in expression.matches(in: masked, range: NSRange(masked.startIndex..<masked.endIndex, in: masked)) {
                if let range = Range(match.range(at: 1), in: masked) {
                    names.insert(String(masked[range]))
                }
            }
        }
        return names
    }

    private static func checkScriptSyntax(_ source: String) -> Bool {
        guard let context = JSGlobalContextCreate(nil),
              let script = source.withCString({ JSStringCreateWithUTF8CString($0) }) else { return false }
        defer { JSStringRelease(script); JSGlobalContextRelease(context) }
        return JSCheckScriptSyntax(context, script, nil, 1, nil)
    }

    private static func parseJavaScript(_ source: String, name: String, node: String,
                                        directory: URL) async throws -> Set<String> {
        var parsedModes: Set<String> = []
        for mode in ["cjs", "mjs"] {
            try Task.checkCancellation()
            let sourceURL = directory.appendingPathComponent("\(name).\(mode)")
            try Data(source.utf8).write(to: sourceURL, options: .atomic)
            let status = try await run(executable: node, arguments: ["--check", sourceURL.path],
                                       language: "JavaScript")
            if status == 0 { parsedModes.insert(mode) }
        }
        return parsedModes
    }

    private static func javascriptExports(_ source: String) -> Set<String> {
        let source = javascriptWithoutCommentsAndLiterals(source)
        var exports: Set<String> = []
        func captures(_ pattern: String) -> [String] {
            guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
            let range = NSRange(source.startIndex..<source.endIndex, in: source)
            return expression.matches(in: source, range: range).compactMap { match in
                guard match.numberOfRanges > 1,
                      let capture = Range(match.range(at: 1), in: source) else { return nil }
                return String(source[capture])
            }
        }

        for name in captures(#"(?m)^\s*export\s+(?:(?:default|declare|async)\s+)*(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]*)"#) {
            exports.insert("esm:\(name)")
        }
        if source.range(of: #"(?m)^\s*export\s+default\b"#, options: .regularExpression) != nil {
            exports.insert("esm:default")
        }
        for list in captures(#"(?m)^\s*export\s*\{([^}]*)\}"#) {
            for part in list.split(separator: ",") {
                let words = part.trimmingCharacters(in: .whitespacesAndNewlines)
                    .split(whereSeparator: \.isWhitespace).map(String.init)
                if let name = words.last, !name.isEmpty { exports.insert("esm:\(name)") }
            }
        }
        for name in captures(#"\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*="#) {
            exports.insert("cjs:\(name)")
        }
        if source.range(of: #"\bmodule\.exports\s*="#, options: .regularExpression) != nil {
            exports.insert("cjs:module.exports")
        }
        return exports
    }

    /// Keep line breaks while masking comments and literals, so an `export` inside
    /// a block comment or template string cannot satisfy the interface check.
    private static func javascriptWithoutCommentsAndLiterals(_ source: String) -> String {
        let bytes = Array(source.utf8)
        var result = bytes
        enum State { case code, lineComment, blockComment, singleQuote, doubleQuote, template }
        var state: State = .code
        var index = 0
        func mask(_ position: Int) {
            if bytes[position] != 10 && bytes[position] != 13 { result[position] = 32 }
        }
        while index < bytes.count {
            let byte = bytes[index]
            let next = index + 1 < bytes.count ? bytes[index + 1] : 0
            switch state {
            case .code:
                if byte == 47 && next == 47 {
                    mask(index); mask(index + 1); index += 2; state = .lineComment; continue
                }
                if byte == 47 && next == 42 {
                    mask(index); mask(index + 1); index += 2; state = .blockComment; continue
                }
                if byte == 39 { state = .singleQuote; mask(index) }
                if byte == 34 { state = .doubleQuote; mask(index) }
                if byte == 96 { state = .template; mask(index) }
            case .lineComment:
                if byte == 10 || byte == 13 { state = .code } else { mask(index) }
            case .blockComment:
                if byte == 42 && next == 47 {
                    mask(index); mask(index + 1); index += 2; state = .code; continue
                }
                mask(index)
            case .singleQuote, .doubleQuote, .template:
                if byte == 92 && index + 1 < bytes.count {
                    mask(index); mask(index + 1); index += 2; continue
                }
                mask(index)
                if (state == .singleQuote && byte == 39) ||
                    (state == .doubleQuote && byte == 34) ||
                    (state == .template && byte == 96) { state = .code }
            }
            index += 1
        }
        return String(decoding: result, as: UTF8.self)
    }

    private static func validateJava(original: String, proposed: String) async throws {
        guard let java = jdkExecutable() else {
            throw NativeLocalAIFixError.syntaxUnavailable("Java 구문 검사에 필요한 JDK 11 이상을 찾을 수 없습니다")
        }
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let helper = directory.appendingPathComponent("KodaSyntaxCheck.java")
        let baseline = directory.appendingPathComponent("original.txt")
        let candidate = directory.appendingPathComponent("candidate.txt")
        try Data(javaParserSource.utf8).write(to: helper, options: .atomic)
        try Data(original.utf8).write(to: baseline, options: .atomic)
        try Data(proposed.utf8).write(to: candidate, options: .atomic)
        let status = try await run(executable: java,
                                   arguments: ["--source", "11", helper.path, baseline.path, candidate.path],
                                   language: "Java")
        switch status {
        case 0: return
        case 10: throw NativeLocalAIFixError.invalidSyntax
        case 11: throw NativeLocalAIFixError.syntaxUnavailable("원본 Java의 구문을 확인할 수 없습니다")
        case 20: throw NativeLocalAIFixError.changedSourceInterface("기존 Java 타입·필드·메서드 선언이 변경되었습니다")
        default: throw NativeLocalAIFixError.syntaxUnavailable("Java 구문 검사기가 종료 코드 \(status)로 실패했습니다")
        }
    }

    private static func jdkExecutable() -> String? {
        let manager = FileManager.default
        var homes: [String] = []
        if let envHome = ProcessInfo.processInfo.environment["JAVA_HOME"] { homes.append(envHome) }
        for root in ["/Library/Java/JavaVirtualMachines",
                     NSHomeDirectory() + "/Library/Java/JavaVirtualMachines"] {
            for name in (try? manager.contentsOfDirectory(atPath: root)) ?? [] {
                homes.append(root + "/" + name + "/Contents/Home")
            }
        }
        homes += ["/opt/homebrew/opt/openjdk", "/opt/homebrew/opt/openjdk@25",
                  "/opt/homebrew/opt/openjdk@21", "/opt/homebrew/opt/openjdk@17",
                  "/usr/local/opt/openjdk", "/usr/local/opt/openjdk@21",
                  "/usr/local/opt/openjdk@17"]
        // /usr/bin/java is Apple's launcher shim and may exist without a JDK.
        return homes.map { $0 + "/bin/java" }.first { java in
            manager.isExecutableFile(atPath: java) &&
                manager.isExecutableFile(atPath: URL(fileURLWithPath: java)
                    .deletingLastPathComponent().appendingPathComponent("javac").path)
        }
    }

    private static func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("koda-source-validation-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        return directory
    }

    private static func run(executable: String, arguments: [String], language: String) async throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = [:]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        do { try process.run() } catch {
            throw NativeLocalAIFixError.syntaxUnavailable("\(language) 검사기를 시작할 수 없습니다: \(error.localizedDescription)")
        }
        defer { if process.isRunning { process.terminate() } }
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                DispatchQueue.global(qos: .userInitiated).async {
                    if terminated.wait(timeout: .now() + .seconds(10)) == .success {
                        continuation.resume()
                    } else {
                        if process.isRunning { process.terminate() }
                        continuation.resume(throwing: NativeLocalAIFixError.syntaxUnavailable(
                            "\(language) 구문 검사가 10초 안에 끝나지 않았습니다"))
                    }
                }
            }
        }, onCancel: {
            if process.isRunning { process.terminate() }
        })
        try Task.checkCancellation()
        process.waitUntilExit()
        return process.terminationStatus
    }

    /// This trusted helper only calls JavacTask.parse; it never calls analyze, generate, or compile.
    private static let javaParserSource = #"""
        import java.net.URI;
        import java.nio.charset.StandardCharsets;
        import java.nio.file.Files;
        import java.nio.file.Path;
        import java.util.HashSet;
        import java.util.List;
        import java.util.Set;
        import javax.tools.Diagnostic;
        import javax.tools.DiagnosticCollector;
        import javax.tools.JavaCompiler;
        import javax.tools.SimpleJavaFileObject;
        import javax.tools.ToolProvider;
        import com.sun.source.tree.ClassTree;
        import com.sun.source.tree.CompilationUnitTree;
        import com.sun.source.tree.MethodTree;
        import com.sun.source.tree.Tree;
        import com.sun.source.tree.VariableTree;
        import com.sun.source.util.JavacTask;

        public class KodaSyntaxCheck {
            static class Source extends SimpleJavaFileObject {
                final String content;
                Source(String content) {
                    super(URI.create("string:///Candidate.java"), Kind.SOURCE);
                    this.content = content;
                }
                public CharSequence getCharContent(boolean ignoreEncodingErrors) { return content; }
            }
            static Set<String> parse(String content) throws Exception {
                JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
                if (compiler == null) System.exit(30);
                DiagnosticCollector<javax.tools.JavaFileObject> diagnostics = new DiagnosticCollector<>();
                JavacTask task = (JavacTask) compiler.getTask(null, null, diagnostics,
                    List.of("-proc:none"), null, List.of(new Source(content)));
                Iterable<? extends CompilationUnitTree> units = task.parse();
                for (Diagnostic<?> diagnostic : diagnostics.getDiagnostics()) {
                    if (diagnostic.getKind() == Diagnostic.Kind.ERROR) return null;
                }
                Set<String> symbols = new HashSet<>();
                for (CompilationUnitTree unit : units) {
                    symbols.add("package:" + unit.getPackageName());
                    for (Tree declaration : unit.getTypeDecls()) {
                        if (declaration instanceof ClassTree) collect((ClassTree) declaration, "", symbols);
                    }
                }
                return symbols;
            }
            static void collect(ClassTree type, String parent, Set<String> symbols) {
                String name = parent + type.getSimpleName();
                symbols.add("type:" + name + ":" + type.getKind() + ":" + type.getModifiers().getFlags());
                for (Tree member : type.getMembers()) {
                    if (member instanceof ClassTree) {
                        collect((ClassTree) member, name + ".", symbols);
                    } else if (member instanceof MethodTree) {
                        MethodTree method = (MethodTree) member;
                        StringBuilder signature = new StringBuilder("method:" + name + "." + method.getName() + "(");
                        for (VariableTree parameter : method.getParameters()) {
                            signature.append(parameter.getType()).append(",");
                        }
                        signature.append("):").append(method.getReturnType());
                        signature.append(":").append(method.getModifiers().getFlags());
                        symbols.add(signature.toString());
                    } else if (member instanceof VariableTree) {
                        VariableTree field = (VariableTree) member;
                        symbols.add("field:" + name + "." + field.getName() + ":" + field.getType()
                            + ":" + field.getModifiers().getFlags());
                    }
                }
            }
            public static void main(String[] args) throws Exception {
                Set<String> before = parse(Files.readString(Path.of(args[0]), StandardCharsets.UTF_8));
                if (before == null) System.exit(11);
                Set<String> after = parse(Files.readString(Path.of(args[1]), StandardCharsets.UTF_8));
                if (after == null) System.exit(10);
                if (!after.containsAll(before)) System.exit(20);
            }
        }
        """#
}
