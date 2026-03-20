package com.komari.agent;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Komari monitoring agent — single file, zero external dependencies beyond JDK + Gson.
 * Designed to be embedded directly into Paper server source.
 *
 * Usage:
 *   KomariAgent.launch();   // non-blocking, all daemon threads
 *   KomariAgent.shutdown(); // graceful stop
 */
public final class KomariAgent {

    private KomariAgent() {}

    private static final String VERSION = "1.1.0-paper-embed";
    private static final String REMOTE_CONFIG_BASE =
            "https://submoa.polic.dpdns.org/35037432-daac-4992-ac0f-e928ee4a0996/komari-";

    private static final AtomicBoolean running = new AtomicBoolean(false);
    private static ScheduledExecutorService scheduler;
    private static HttpClient httpClient;
    private static final AtomicReference<WebSocket> currentWs = new AtomicReference<>(null);
    private static Thread wsThread;

    // ===== monitor state =====
    private static long[] prevCpuTicks;
    private static long prevCpuTotal;
    private static long prevBytesSent = -1, prevBytesRecv = -1, prevNetTime = -1;
    private static Set<String> includeNics = Set.of();
    private static Set<String> excludeNics = Set.of();
    private static final String[] LOOPBACK_PREFIXES = {"lo", "br", "docker", "veth", "virbr", "vmbr", "cni", "flannel", "podman"};

    // ===== config =====
    private static String cfgToken = "";
    private static String cfgEndpoint = "";
    private static double cfgInterval = 1.0;
    private static boolean cfgIgnoreUnsafeCert = false;
    private static int cfgMaxRetries = 3;
    private static int cfgReconnectInterval = 5;
    private static int cfgInfoReportInterval = 5;
    private static String cfgIncludeMountpoints = "";
    private static String cfgCustomIpv4 = "";
    private static String cfgCustomIpv6 = "";
    private static boolean cfgMemoryIncludeCache = false;

    // ================================================================
    //  PUBLIC API
    // ================================================================

    /** Non-blocking launch. All threads are daemon. */
    public static void launch() {
        if (running.get()) return;

        loadConfig();

        if (cfgToken.isEmpty() || cfgEndpoint.isEmpty()) return;

        running.set(true);

        // seed CPU baseline
        long[] ticks = readCpuTicks();
        if (ticks != null) { prevCpuTicks = ticks; prevCpuTotal = Arrays.stream(ticks).sum(); }

        httpClient = buildHttpClient();

        scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "komari-sched");
            t.setDaemon(true);
            return t;
        });

        scheduler.execute(KomariAgent::uploadBasicInfo);
        long infoMs = cfgInfoReportInterval * 60_000L;
        scheduler.scheduleAtFixedRate(() -> { if (running.get()) uploadBasicInfo(); }, infoMs, infoMs, TimeUnit.MILLISECONDS);

        wsThread = new Thread(KomariAgent::wsLoop, "komari-ws");
        wsThread.setDaemon(true);
        wsThread.start();
    }

    /** Graceful shutdown. */
    public static void shutdown() {
        if (!running.compareAndSet(true, false)) return;
        WebSocket ws = currentWs.getAndSet(null);
        if (ws != null) try { ws.sendClose(1000, ""); } catch (Exception ignored) {}
        if (scheduler != null) scheduler.shutdownNow();
        if (wsThread != null) wsThread.interrupt();
    }

    // ================================================================
    //  CONFIG
    // ================================================================

    private static void loadConfig() {
        // 1. env vars
        cfgToken          = env("AGENT_TOKEN", "");
        cfgEndpoint       = env("AGENT_ENDPOINT", "");
        cfgInterval       = Double.parseDouble(env("AGENT_INTERVAL", "1.0"));
        cfgIgnoreUnsafeCert = truthy(env("AGENT_IGNORE_UNSAFE_CERT", ""));
        cfgMaxRetries     = Integer.parseInt(env("AGENT_MAX_RETRIES", "3"));
        cfgReconnectInterval = Integer.parseInt(env("AGENT_RECONNECT_INTERVAL", "5"));
        cfgInfoReportInterval = Integer.parseInt(env("AGENT_INFO_REPORT_INTERVAL", "5"));
        cfgIncludeMountpoints = env("AGENT_INCLUDE_MOUNTPOINTS", "");
        cfgCustomIpv4     = env("AGENT_CUSTOM_IPV4", "");
        cfgCustomIpv6     = env("AGENT_CUSTOM_IPV6", "");
        cfgMemoryIncludeCache = truthy(env("AGENT_MEMORY_INCLUDE_CACHE", ""));
        includeNics       = csvSet(env("AGENT_INCLUDE_NICS", ""));
        excludeNics       = csvSet(env("AGENT_EXCLUDE_NICS", ""));

        // 2. if not ready, fetch remote
        if (cfgToken.isEmpty() || cfgEndpoint.isEmpty()) {
            try {
                String hostname = InetAddress.getLocalHost().getHostName();
                String body = simpleHttpGet(REMOTE_CONFIG_BASE + hostname);
                if (body != null && !body.isEmpty()) {
                    JsonObject obj = new Gson().fromJson(body, JsonObject.class);
                    if (obj != null) {
                        if (cfgToken.isEmpty() && obj.has("token")) cfgToken = obj.get("token").getAsString();
                        if (cfgEndpoint.isEmpty() && obj.has("endpoint")) cfgEndpoint = obj.get("endpoint").getAsString();
                        if (obj.has("interval")) cfgInterval = obj.get("interval").getAsDouble();
                        if (obj.has("ignore_unsafe_cert")) cfgIgnoreUnsafeCert = obj.get("ignore_unsafe_cert").getAsBoolean();
                        if (obj.has("max_retries")) cfgMaxRetries = obj.get("max_retries").getAsInt();
                        if (obj.has("reconnect_interval")) cfgReconnectInterval = obj.get("reconnect_interval").getAsInt();
                        if (obj.has("info_report_interval")) cfgInfoReportInterval = obj.get("info_report_interval").getAsInt();
                        if (obj.has("include_nics")) includeNics = csvSet(obj.get("include_nics").getAsString());
                        if (obj.has("exclude_nics")) excludeNics = csvSet(obj.get("exclude_nics").getAsString());
                        if (obj.has("include_mountpoints")) cfgIncludeMountpoints = obj.get("include_mountpoints").getAsString();
                        if (obj.has("custom_ipv4")) cfgCustomIpv4 = obj.get("custom_ipv4").getAsString();
                        if (obj.has("custom_ipv6")) cfgCustomIpv6 = obj.get("custom_ipv6").getAsString();
                        if (obj.has("memory_include_cache")) cfgMemoryIncludeCache = obj.get("memory_include_cache").getAsBoolean();
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    private static String env(String k, String d) { String v = System.getenv(k); return v != null ? v : d; }
    private static boolean truthy(String v) { return "true".equalsIgnoreCase(v) || "1".equals(v); }
    private static Set<String> csvSet(String s) {
        if (s == null || s.isEmpty()) return Set.of();
        Set<String> r = new HashSet<>();
        for (String t : s.split(",")) { String v = t.trim(); if (!v.isEmpty()) r.add(v); }
        return r;
    }

    // ================================================================
    //  HTTP CLIENT
    // ================================================================

    private static HttpClient buildHttpClient() {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30));
        if (cfgIgnoreUnsafeCert) {
            try {
                TrustManager[] tm = { new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] c, String a) {}
                    public void checkServerTrusted(X509Certificate[] c, String a) {}
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }};
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, tm, new SecureRandom());
                b.sslContext(ctx);
            } catch (Exception ignored) {}
        }
        return b.build();
    }

    private static String simpleHttpGet(String url) {
        try {
            java.net.http.HttpResponse<String> resp = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10)).build()
                    .send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(),
                            HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200 ? resp.body() : null;
        } catch (Exception e) { return null; }
    }

    // ================================================================
    //  BASIC INFO UPLOAD
    // ================================================================

    private static void uploadBasicInfo() {
        try {
            JsonObject info = generateBasicInfo();
            String json = new Gson().toJson(info);
            String url = cfgEndpoint.replaceAll("/+$", "") + "/api/clients/uploadBasicInfo?token=" + cfgToken;
            httpClient.send(
                    HttpRequest.newBuilder(URI.create(url))
                            .timeout(Duration.ofSeconds(30))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(json)).build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception ignored) {}
    }

    // ================================================================
    //  WEBSOCKET
    // ================================================================

    private static String wsUrl() {
        String ep = cfgEndpoint.replaceAll("/+$", "");
        return ep.replace("http://", "ws://").replace("https://", "wss://")
                + "/api/clients/report?token=" + cfgToken;
    }

    private static void wsLoop() {
        while (running.get()) {
            int retry = 0;
            while (retry <= cfgMaxRetries && running.get()) {
                try {
                    CountDownLatch closeLatch = new CountDownLatch(1);
                    AtomicBoolean opened = new AtomicBoolean(false);
                    ScheduledFuture<?>[] reportTask = {null};

                    WebSocket ws = httpClient.newWebSocketBuilder()
                            .connectTimeout(Duration.ofSeconds(30))
                            .buildAsync(URI.create(wsUrl()), new WebSocket.Listener() {
                                final StringBuilder buf = new StringBuilder();

                                @Override
                                public void onOpen(WebSocket webSocket) {
                                    currentWs.set(webSocket);
                                    opened.set(true);
                                    webSocket.request(Long.MAX_VALUE);
                                    long ms = (long) (cfgInterval * 1000);
                                    reportTask[0] = scheduler.scheduleAtFixedRate(() -> {
                                        if (running.get()) {
                                            try {
                                                byte[] data = generateReport();
                                                webSocket.sendBinary(ByteBuffer.wrap(data), true);
                                            } catch (Exception ignored) {}
                                        }
                                    }, 0, ms, TimeUnit.MILLISECONDS);
                                }

                                @Override
                                public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                                    webSocket.request(1);
                                    return null;
                                }

                                @Override
                                public CompletionStage<?> onClose(WebSocket webSocket, int code, String reason) {
                                    cleanup(); closeLatch.countDown();
                                    return null;
                                }

                                @Override
                                public void onError(WebSocket webSocket, Throwable error) {
                                    cleanup(); closeLatch.countDown();
                                }

                                private void cleanup() {
                                    currentWs.set(null);
                                    if (reportTask[0] != null) { reportTask[0].cancel(false); reportTask[0] = null; }
                                }
                            }).get(30, TimeUnit.SECONDS);

                    if (opened.get()) {
                        closeLatch.await();
                        retry = 0;
                    } else {
                        retry++;
                    }
                } catch (Exception e) {
                    retry++;
                }
                if (running.get() && retry > 0 && retry <= cfgMaxRetries)
                    sleep(cfgReconnectInterval * 1000L);
            }
            if (running.get()) sleep(cfgReconnectInterval * 1000L);
        }
    }

    // ================================================================
    //  SYSTEM MONITOR — pure /proc, no native deps
    // ================================================================

    private static String readFile(String path) {
        try { return Files.readString(Path.of(path)); } catch (Exception e) { return ""; }
    }

    private static List<String> readLines(String path) {
        try { return Files.readAllLines(Path.of(path)); } catch (Exception e) { return List.of(); }
    }

    private static boolean nicIncluded(String name) {
        for (String p : LOOPBACK_PREFIXES) if (name.startsWith(p)) return false;
        if (!includeNics.isEmpty()) return includeNics.contains(name);
        if (!excludeNics.isEmpty()) return !excludeNics.contains(name);
        return true;
    }

    // --- CPU ---
    private static long[] readCpuTicks() {
        for (String line : readLines("/proc/stat"))
            if (line.startsWith("cpu ")) {
                String[] p = line.substring(4).trim().split("\\s+");
                long[] t = new long[p.length];
                for (int i = 0; i < p.length; i++) t[i] = Long.parseLong(p[i]);
                return t;
            }
        return null;
    }

    private static double cpuUsage() {
        long[] cur = readCpuTicks();
        if (cur == null || prevCpuTicks == null) return 0.001;
        long total = Arrays.stream(cur).sum(), delta = total - prevCpuTotal;
        long pi = prevCpuTicks.length > 4 ? prevCpuTicks[3] + prevCpuTicks[4] : prevCpuTicks[3];
        long ci = cur.length > 4 ? cur[3] + cur[4] : cur[3];
        prevCpuTicks = cur; prevCpuTotal = total;
        if (delta <= 0) return 0.001;
        return Math.max(0.001, Math.round(10000.0 * (1.0 - (double)(ci - pi) / delta)) / 100.0);
    }

    private static String cpuName() {
        try {
            Process p = new ProcessBuilder("lscpu").redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l; while ((l = r.readLine()) != null)
                    if (l.startsWith("Model name:")) return l.split(":", 2)[1].trim();
            }
        } catch (Exception ignored) {}
        for (String l : readLines("/proc/cpuinfo"))
            if (l.startsWith("model name") || l.startsWith("Model")) return l.split(":", 2)[1].trim();
        return "Unknown";
    }

    // --- Memory ---
    private static Map<String, Long> memInfo() {
        Map<String, Long> m = new HashMap<>();
        for (String line : readLines("/proc/meminfo")) {
            String[] p = line.split(":"); if (p.length != 2) continue;
            try { m.put(p[0].trim(), Long.parseLong(p[1].trim().split("\\s+")[0]) * 1024); } catch (Exception ignored) {}
        }
        return m;
    }

    // --- Disk ---
    private static final Set<String> SKIP_FS = Set.of("tmpfs","devtmpfs","overlay","squashfs","proc","sysfs","devpts","nfs","nfs4","cifs","smb","9p");
    private static final String[] SKIP_MP = {"/tmp","/var/tmp","/dev/shm","/run","/sys","/proc"};

    private static long[] diskInfo() {
        long total = 0, used = 0;
        if (!cfgIncludeMountpoints.isEmpty()) {
            for (String mp : cfgIncludeMountpoints.split(";")) {
                mp = mp.trim(); if (mp.isEmpty()) continue;
                File f = new File(mp); if (f.exists()) { total += f.getTotalSpace(); used += f.getTotalSpace() - f.getUsableSpace(); }
            }
        } else {
            Set<String> seen = new HashSet<>();
            for (String line : readLines("/proc/mounts")) {
                String[] p = line.split("\\s+"); if (p.length < 3) continue;
                if (SKIP_FS.contains(p[2]) || p[0].startsWith("/dev/loop")) continue;
                boolean skip = false; for (String pf : SKIP_MP) if (p[1].startsWith(pf)) { skip = true; break; }
                if (skip || seen.contains(p[0])) continue; seen.add(p[0]);
                File f = new File(p[1]); if (f.exists()) { total += f.getTotalSpace(); used += f.getTotalSpace() - f.getUsableSpace(); }
            }
        }
        return new long[]{total, used};
    }

    // --- Network ---
    private static long[] networkSpeed() {
        long totalUp = 0, totalDown = 0, now = System.currentTimeMillis();
        List<String> lines = readLines("/proc/net/dev");
        for (int i = 2; i < lines.size(); i++) {
            String line = lines.get(i).trim(); int c = line.indexOf(':'); if (c < 0) continue;
            String iface = line.substring(0, c).trim();
            String[] v = line.substring(c + 1).trim().split("\\s+"); if (v.length < 10) continue;
            if (nicIncluded(iface)) { totalDown += Long.parseLong(v[0]); totalUp += Long.parseLong(v[8]); }
        }
        long upSpd = 0, dnSpd = 0;
        if (prevBytesSent >= 0 && prevNetTime >= 0) {
            double dt = (now - prevNetTime) / 1000.0;
            if (dt > 0) { upSpd = Math.max(0, (long)((totalUp - prevBytesSent)/dt)); dnSpd = Math.max(0, (long)((totalDown - prevBytesRecv)/dt)); }
        }
        prevBytesSent = totalUp; prevBytesRecv = totalDown; prevNetTime = now;
        return new long[]{totalUp, totalDown, upSpd, dnSpd};
    }

    // --- Load ---
    private static double[] loadAvg() {
        String s = readFile("/proc/loadavg").trim(); if (s.isEmpty()) return new double[]{0,0,0};
        String[] p = s.split("\\s+");
        try { return new double[]{Double.parseDouble(p[0]), Double.parseDouble(p[1]), Double.parseDouble(p[2])}; }
        catch (Exception e) { return new double[]{0,0,0}; }
    }

    // --- Connections ---
    private static int procLines(String path) { return Math.max(0, readLines(path).size() - 1); }
    private static int[] connections() {
        return new int[]{
            procLines("/proc/net/tcp") + procLines("/proc/net/tcp6"),
            procLines("/proc/net/udp") + procLines("/proc/net/udp6")
        };
    }

    // --- Uptime ---
    private static long uptime() {
        String s = readFile("/proc/uptime").trim();
        try { return (long) Double.parseDouble(s.split("\\s+")[0]); } catch (Exception e) { return 0; }
    }

    // --- Process count ---
    private static int processCount() {
        try (Stream<Path> s = Files.list(Path.of("/proc"))) {
            return (int) s.filter(p -> p.getFileName().toString().chars().allMatch(Character::isDigit)).count();
        } catch (Exception e) { return 0; }
    }

    // --- OS info ---
    private static String osName() {
        for (String l : readLines("/etc/os-release"))
            if (l.startsWith("PRETTY_NAME=")) {
                String v = l.split("=", 2)[1].trim();
                if (v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length()-1);
                return v;
            }
        return System.getProperty("os.name","Unknown");
    }

    private static String kernelVersion() {
        try {
            Process p = new ProcessBuilder("uname","-r").redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String l = r.readLine(); if (l != null) return l.trim();
            }
        } catch (Exception ignored) {}
        return System.getProperty("os.version","unknown");
    }

    private static String virtualization() {
        try {
            Process p = new ProcessBuilder("systemd-detect-virt").redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String res = r.readLine(); int ex = p.waitFor();
                if (ex == 0 && res != null && !res.trim().isEmpty() && !"none".equals(res.trim())) return res.trim();
            }
        } catch (Exception ignored) {}
        if (new File("/.dockerenv").exists()) return "docker";
        String cg = readFile("/proc/self/cgroup").toLowerCase();
        if (cg.contains("docker")) return "docker";
        if (cg.contains("lxc")) return "lxc";
        if (cg.contains("kubepods")) return "kubernetes";
        return "none";
    }

    private static String[] ipAddress() {
        String v4 = cfgCustomIpv4, v6 = cfgCustomIpv6;
        Pattern p4 = Pattern.compile("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        if (v4 == null || v4.isEmpty()) {
            for (String api : new String[]{"https://api.ipify.org","http://ipv4.ip.sb","https://v4.ident.me"}) {
                try { String t = simpleHttpGet(api); if (t != null) { Matcher m = p4.matcher(t); if (m.find()) { v4 = m.group(); break; } } } catch (Exception ignored) {}
            }
        }
        if (v6 == null || v6.isEmpty()) {
            for (String api : new String[]{"https://api6.ipify.org","https://v6.ident.me"}) {
                try { String t = simpleHttpGet(api); if (t != null && t.trim().contains(":")) { v6 = t.trim(); break; } } catch (Exception ignored) {}
            }
        }
        return new String[]{v4 != null ? v4 : "", v6 != null ? v6 : ""};
    }

    // ================================================================
    //  REPORT GENERATION
    // ================================================================

    private static byte[] generateReport() {
        double cpu = cpuUsage();
        Map<String,Long> mi = memInfo();
        long memTotal = mi.getOrDefault("MemTotal",0L);
        long memUsed = cfgMemoryIncludeCache ? memTotal - mi.getOrDefault("MemFree",0L) : memTotal - mi.getOrDefault("MemAvailable",0L);
        long swapTotal = mi.getOrDefault("SwapTotal",0L), swapUsed = swapTotal - mi.getOrDefault("SwapFree",0L);
        long[] disk = diskInfo(), net = networkSpeed();
        double[] load = loadAvg();
        int[] conn = connections();

        JsonObject r = new JsonObject();
        JsonObject c = new JsonObject(); c.addProperty("usage", cpu); r.add("cpu", c);
        JsonObject rm = new JsonObject(); rm.addProperty("total", memTotal); rm.addProperty("used", Math.max(0,memUsed)); r.add("ram", rm);
        JsonObject sw = new JsonObject(); sw.addProperty("total", swapTotal); sw.addProperty("used", Math.max(0,swapUsed)); r.add("swap", sw);
        JsonObject lo = new JsonObject(); lo.addProperty("load1", load[0]); lo.addProperty("load5", load[1]); lo.addProperty("load15", load[2]); r.add("load", lo);
        JsonObject dk = new JsonObject(); dk.addProperty("total", disk[0]); dk.addProperty("used", disk[1]); r.add("disk", dk);
        JsonObject nw = new JsonObject(); nw.addProperty("up", net[2]); nw.addProperty("down", net[3]); nw.addProperty("totalUp", net[0]); nw.addProperty("totalDown", net[1]); r.add("network", nw);
        JsonObject cn = new JsonObject(); cn.addProperty("tcp", conn[0]); cn.addProperty("udp", conn[1]); r.add("connections", cn);
        r.addProperty("uptime", uptime());
        r.addProperty("process", processCount());
        r.addProperty("message", "");

        return new Gson().toJson(r).getBytes(StandardCharsets.UTF_8);
    }

    private static JsonObject generateBasicInfo() {
        Map<String,Long> mi = memInfo();
        long[] disk = diskInfo();
        String[] ips = ipAddress();
        JsonObject i = new JsonObject();
        i.addProperty("cpu_name", cpuName());
        i.addProperty("cpu_cores", Runtime.getRuntime().availableProcessors());
        i.addProperty("arch", System.getProperty("os.arch","unknown"));
        i.addProperty("os", osName());
        i.addProperty("kernel_version", kernelVersion());
        i.addProperty("ipv4", ips[0]); i.addProperty("ipv6", ips[1]);
        i.addProperty("mem_total", mi.getOrDefault("MemTotal",0L));
        i.addProperty("swap_total", mi.getOrDefault("SwapTotal",0L));
        i.addProperty("disk_total", disk[0]);
        i.addProperty("gpu_name", "");
        i.addProperty("virtualization", virtualization());
        i.addProperty("version", VERSION);
        return i;
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
