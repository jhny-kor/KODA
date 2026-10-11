#!/usr/bin/env python3
"""Compile the actual Swift client and exercise it against a loopback fixture."""
import http.server
import json
from pathlib import Path
import subprocess
import tempfile
import threading

SOURCE = Path(__file__).resolve().parents[1] / 'app/KODA/KODA/LocalAIClient.swift'
requests = []
stop_event = threading.Event()

class Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        requests.append((self.path, self.headers.get('Authorization')))
        if self.path == '/redirect/models':
            self.send_response(302)
            self.send_header('Location', '/unexpected/models')
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({'data': [{'id': 'fixture'}, {'id': 'fixture'}]}).encode())

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body['model'] == 'fixture'
        assert body['stream'] is (self.path in ['/stream/chat/completions', '/reasoning/chat/completions'])
        assert body['messages'][0]['role'] == 'system'
        requests.append((self.path, self.headers.get('Authorization')))
        if self.path in ['/stream/chat/completions', '/reasoning/chat/completions']:
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            if self.path == '/reasoning/chat/completions':
                for _ in range(20):
                    reasoning = {'choices': [{'delta': {'reasoning_content': 'x' * 60000}, 'finish_reason': None}]}
                    self.wfile.write(('data: ' + json.dumps(reasoning) + '\n\n').encode())
            for chunk in [
                {'choices': [{'delta': {'content': 'safe '}, 'finish_reason': None}]},
                {'choices': [{'delta': {'content': 'source'}, 'finish_reason': None}]},
                {'choices': [{'delta': {}, 'finish_reason': 'stop'}]},
            ]:
                self.wfile.write(('data: ' + json.dumps(chunk) + '\n\n').encode())
                self.wfile.flush()
            self.wfile.write(b'data: [DONE]\n\n')
            self.wfile.flush()
            return
        if self.path == '/slow/chat/completions':
            stop_event.wait(5)
        self.send_response(503 if self.path == '/error/chat/completions' else 200)
        if self.path == '/large/chat/completions':
            self.send_header('Content-Length', '1048577')
            self.end_headers()
            try:
                self.wfile.write(b'x' * 1048577)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.end_headers()
        if self.path == '/malformed/chat/completions':
            payload = b'not-json'
        else:
            content = '' if self.path == '/empty/chat/completions' else '검증 완료'
            payload = json.dumps({'choices': [{'message': {'content': content}}]}).encode()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Server)
server.daemon_threads = False
server_thread = threading.Thread(target=server.serve_forever)
server_thread.start()
port = server.server_address[1]
harness = '''
import Foundation
@main struct Test {
    static func main() async throws {
        let client = LocalAIClient()
        var config = LocalAIConfiguration(baseURL: "http://127.0.0.1:PORT/v1", model: "fixture", apiKey: "")
        let models = try await client.models(configuration: config)
        precondition(models == ["fixture"])
        config.apiKey = "test-token"
        let answer = try await client.complete(configuration: config, prompt: "test")
        precondition(answer == "검증 완료")
        config.baseURL = "http://127.0.0.1:PORT/stream"
        let streamed = try await client.completeStreaming(configuration: config, prompt: "test", system: "Return source")
        precondition(streamed == "safe source")
        config.baseURL = "http://127.0.0.1:PORT/reasoning"
        let afterReasoning = try await client.completeStreaming(configuration: config, prompt: "test", system: "Return source")
        precondition(afterReasoning == "safe source")
        let truncated = Data("data: {\\"choices\\":[{\\"delta\\":{},\\"finish_reason\\":\\"length\\"}]}\\n\\ndata: [DONE]\\n\\n".utf8)
        do { _ = try LocalAIClient.streamingContent(from: truncated); fatalError("accepted truncated stream") }
        catch LocalAIError.outputLimitReached { }
        let reasoningOnly = Data("data: {\\"choices\\":[{\\"delta\\":{\\"reasoning_content\\":\\"thinking\\"},\\"finish_reason\\":null}]}\\n\\ndata: {\\"choices\\":[{\\"delta\\":{},\\"finish_reason\\":\\"length\\"}]}\\n\\ndata: [DONE]\\n\\n".utf8)
        do { _ = try LocalAIClient.streamingContent(from: reasoningOnly); fatalError("accepted reasoning-only stream") }
        catch LocalAIError.reasoningOnly { }
        let interrupted = Data("data: {\\"choices\\":[{\\"delta\\":{\\"content\\":\\"partial\\"},\\"finish_reason\\":null}]}\\n\\n".utf8)
        do { _ = try LocalAIClient.streamingContent(from: interrupted); fatalError("accepted interrupted stream") }
        catch LocalAIError.incompleteGeneration { }
        config.baseURL = "http://127.0.0.1:PORT/v1"
        for base in ["https://example.com/v1", "http://127.0.0.1.evil.com/v1", "http://user@localhost/v1", "http://localhost/v1?token=x", "http://localhost/v1#x"] {
            config.baseURL = base
            do { _ = try LocalAIClient.endpoint(configuration: config, resource: "models"); fatalError("accepted unsafe endpoint") }
            catch LocalAIError.invalidEndpoint { }
        }
        config.baseURL = "http://[::1]:1234/v1"
        _ = try LocalAIClient.endpoint(configuration: config, resource: "models")
        config.baseURL = "http://127.0.0.1:PORT/redirect"
        do { _ = try await client.models(configuration: config); fatalError("redirect accepted") }
        catch LocalAIError.http(302) { }
        config.baseURL = "http://127.0.0.1:PORT/large"
        do { _ = try await client.complete(configuration: config, prompt: "test"); fatalError("oversize accepted") }
        catch LocalAIError.responseTooLarge { }
        config.baseURL = "http://127.0.0.1:PORT/malformed"
        do { _ = try await client.complete(configuration: config, prompt: "test"); fatalError("malformed JSON accepted") }
        catch LocalAIError.invalidResponse { }
        config.baseURL = "http://127.0.0.1:PORT/empty"
        do { _ = try await client.complete(configuration: config, prompt: "test"); fatalError("empty completion accepted") }
        catch LocalAIError.emptyResponse { }
        config.baseURL = "http://127.0.0.1:PORT/error"
        do { _ = try await client.complete(configuration: config, prompt: "test"); fatalError("HTTP error accepted") }
        catch LocalAIError.http(503) { }
        config.baseURL = "http://127.0.0.1:PORT/slow"
        let delayedConfiguration = config
        let delayed = Task { try await client.complete(configuration: delayedConfiguration, prompt: "test") }
        try await Task.sleep(nanoseconds: 300_000_000)
        let cancelledAt = Date()
        delayed.cancel()
        do { _ = try await delayed.value; fatalError("cancelled request succeeded") }
        catch is CancellationError { }
        catch let error as URLError where error.code == .cancelled { }
        precondition(Date().timeIntervalSince(cancelledAt) < 2, "cancellation was not prompt")
        config.apiKey = "invalid\\nkey"
        do { _ = try await client.models(configuration: config); fatalError("invalid key accepted") }
        catch LocalAIError.invalidKey { }
        print("LocalAIClient fixture tests passed")
    }
}
'''.replace('PORT', str(port))
try:
    with tempfile.TemporaryDirectory(prefix='koda-local-ai-tests-') as directory:
        directory = Path(directory)
        (directory / 'Harness.swift').write_text(harness)
        subprocess.run(['swiftc', str(SOURCE), str(directory / 'Harness.swift'), '-o', str(directory / 'test')], check=True)
        subprocess.run([str(directory / 'test')], check=True, timeout=30)
    assert requests == [('/v1/models', None), ('/v1/chat/completions', 'Bearer test-token'), ('/stream/chat/completions', 'Bearer test-token'), ('/reasoning/chat/completions', 'Bearer test-token'), ('/redirect/models', 'Bearer test-token'), ('/large/chat/completions', 'Bearer test-token'), ('/malformed/chat/completions', 'Bearer test-token'), ('/empty/chat/completions', 'Bearer test-token'), ('/error/chat/completions', 'Bearer test-token'), ('/slow/chat/completions', 'Bearer test-token')], requests
finally:
    stop_event.set()
    server.shutdown()
    server.server_close()
    server_thread.join(timeout=2)
    assert not server_thread.is_alive()
