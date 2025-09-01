import com.sun.net.httpserver.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class app {
    // --- simple in-memory stores (demo) ---
    static class User {
        String username;
        byte[] pwdSalt;      // for hashing
        byte[] pwdHash;      // PBKDF2 hashed password
        byte[] aesSalt;      // salt used to derive AES key for entries
        User(String u, byte[] pSalt, byte[] pHash, byte[] aSalt) {
            username = u; pwdSalt = pSalt; pwdHash = pHash; aesSalt = aSalt;
        }
    }
    static class Entry {
        String id;
        String site;
        String account;
        String ivB64;
        String ctB64;
        Entry(String id, String site, String account, String ivB64, String ctB64){
            this.id = id; this.site = site; this.account = account; this.ivB64 = ivB64; this.ctB64 = ctB64;
        }
    }
    static Map<String,User> users = new ConcurrentHashMap<>();                 // username -> User
    static Map<String, List<Entry>> vault = new ConcurrentHashMap<>();        // username -> entries
    static class Session { String username; byte[] aesKey; long exp; Session(String u, byte[] k, long e){ username=u; aesKey=k; exp=e; } }
    static Map<String, Session> sessions = new ConcurrentHashMap<>();         // token -> Session

    static SecureRandom RNG = new SecureRandom();

    public static void main(String[] args) throws Exception {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/register", wrap((req, res) -> handleRegister(req, res)));
        server.createContext("/login", wrap((req, res) -> handleLogin(req, res)));
        server.createContext("/passwords", wrap((req, res) -> {
            if ("GET".equals(req.getRequestMethod())) handleList(req,res);
            else if ("POST".equals(req.getRequestMethod())) handleAdd(req,res);
            else sendJSON(res, 405, jsonMsg("Method not allowed"));
        }));
        server.createContext("/passwords/", wrap((req, res) -> { // DELETE to /passwords/{id}
            if ("DELETE".equals(req.getRequestMethod())) handleDelete(req,res);
            else sendJSON(res, 405, jsonMsg("Method not allowed"));
        }));
        server.createContext("/logout", wrap((req,res)-> handleLogout(req,res)));
        server.createContext("/health", wrap((req,res)-> sendJSON(res,200,"{\"ok\":true}")));

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("Server started at http://localhost:" + port);
    }

    // ----- Handlers -----
    static void handleRegister(HttpExchange ex, Response res) throws Exception {
        String body = readAll(ex);
        Map<String,String> data = parseJson(body);
        String user = safeGet(data,"user");
        String pass = safeGet(data,"pass");
        if (user.isEmpty() || pass.length() < 6) { sendJSON(res,400, jsonMsg("username and 6+ char password required")); return; }
        if (users.containsKey(user)) { sendJSON(res,400,jsonMsg("user exists")); return; }

        byte[] pwdSalt = new byte[16]; RNG.nextBytes(pwdSalt);
        byte[] pwdHash = pbkdf2(pass.toCharArray(), pwdSalt, 120_000, 256);
        byte[] aesSalt = new byte[16]; RNG.nextBytes(aesSalt);
        users.put(user, new User(user, pwdSalt, pwdHash, aesSalt));
        vault.put(user, new CopyOnWriteArrayList<>());
        sendJSON(res,200, jsonMsg("registered"));
    }

    static void handleLogin(HttpExchange ex, Response res) throws Exception {
        String body = readAll(ex);
        Map<String,String> data = parseJson(body);
        String user = safeGet(data,"user");
        String pass = safeGet(data,"pass");
        User u = users.get(user);
        if (u==null) { sendJSON(res,401,jsonMsg("invalid credentials")); return; }
        byte[] check = pbkdf2(pass.toCharArray(), u.pwdSalt, 120_000, 256);
        if (!constantTimeEq(check, u.pwdHash)) { sendJSON(res,401,jsonMsg("invalid credentials")); return; }

        // derive AES key for this session (per-user, derived from password + user.aesSalt)
        byte[] aesKey = pbkdf2(pass.toCharArray(), u.aesSalt, 120_000, 256);
        String token = UUID.randomUUID().toString();
        long exp = Instant.now().getEpochSecond() + 30*60; // 30 min
        sessions.put(token, new Session(user, aesKey, exp));
        String json = "{\"token\":\""+token+"\",\"user\":\""+user+"\"}";
        sendJSON(res,200,json);
    }

    static void handleAdd(HttpExchange ex, Response res) throws Exception {
        Session s = authSession(ex);
        if (s==null) { sendJSON(res,401,jsonMsg("unauthorized")); return; }
        String body = readAll(ex);
        Map<String,String> data = parseJson(body);
        String site = safeGet(data,"site");
        String account = safeGet(data,"account");
        String secret = safeGet(data,"secret");
        if (site.isEmpty() || account.isEmpty() || secret.isEmpty()) { sendJSON(res,400,jsonMsg("site/account/secret required")); return; }

        // encrypt secret with AES-GCM using session.aesKey
        EncResult r = aesGcmEncrypt(s.aesKey, secret.getBytes(StandardCharsets.UTF_8));
        Entry e = new Entry(UUID.randomUUID().toString(), site, account, Base64.getEncoder().encodeToString(r.iv), Base64.getEncoder().encodeToString(r.ct));
        vault.get(s.username).add(e);
        sendJSON(res,200, "{\"id\":\""+e.id+"\",\"site\":\""+escape(site)+"\",\"account\":\""+escape(account)+"\"}");
    }

    static void handleList(HttpExchange ex, Response res) throws Exception {
        Session s = authSession(ex);
        if (s==null) { sendJSON(res,401,jsonMsg("unauthorized")); return; }
        List<Entry> list = vault.getOrDefault(s.username, Collections.emptyList());
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (Entry e : list) {
            byte[] iv = Base64.getDecoder().decode(e.ivB64);
            byte[] ct = Base64.getDecoder().decode(e.ctB64);
            String plain = new String(aesGcmDecrypt(s.aesKey, iv, ct), StandardCharsets.UTF_8);
            if (!first) sb.append(",");
            sb.append("{");
            sb.append("\"id\":\"").append(e.id).append("\",");
            sb.append("\"site\":\"").append(escape(e.site)).append("\",");
            sb.append("\"account\":\"").append(escape(e.account)).append("\",");
            sb.append("\"secret\":\"").append(escape(plain)).append("\"");
            sb.append("}");
            first = false;
        }
        sb.append("]");
        sendJSON(res,200, sb.toString());
    }

    static void handleDelete(HttpExchange ex, Response res) throws Exception {
        Session s = authSession(ex);
        if (s==null) { sendJSON(res,401,jsonMsg("unauthorized")); return; }
        String path = ex.getRequestURI().getPath(); // /passwords/{id}
        String id = path.substring("/passwords/".length());
        List<Entry> list = vault.getOrDefault(s.username, Collections.emptyList());
        boolean removed = list.removeIf(en -> en.id.equals(id));
        sendJSON(res, 200, jsonMsg(removed ? "deleted":"not found"));
    }

    static void handleLogout(HttpExchange ex, Response res) throws Exception {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            String token = auth.substring(7);
            sessions.remove(token);
        }
        sendJSON(res,200,jsonMsg("logged out"));
    }

    // ----- Utilities -----
    static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLen) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLen);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    static boolean constantTimeEq(byte[] a, byte[] b){
        if (a.length != b.length) return false;
        int r = 0;
        for (int i=0;i<a.length;i++) r |= a[i] ^ b[i];
        return r == 0;
    }

    static class EncResult { byte[] iv; byte[] ct; }
    static EncResult aesGcmEncrypt(byte[] key, byte[] plain) throws Exception {
        byte[] iv = new byte[12]; RNG.nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec k = new SecretKeySpec(key, 0, 16, "AES"); // use first 128 bits
        c.init(Cipher.ENCRYPT_MODE, k, spec);
        byte[] ct = c.doFinal(plain);
        EncResult r = new EncResult(); r.iv=iv; r.ct=ct; return r;
    }
    static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec k = new SecretKeySpec(key, 0, 16, "AES");
        c.init(Cipher.DECRYPT_MODE, k, spec);
        return c.doFinal(ct);
    }

    static String readAll(HttpExchange ex) throws IOException {
        InputStream in = ex.getRequestBody();
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int r;
        while ((r = in.read(buf)) != -1) bout.write(buf,0,r);
        return new String(bout.toByteArray(), StandardCharsets.UTF_8);
    }

    // very small JSON extractor for flat objects (string values only). Not a full JSON parser,
    // but sufficient for our small client payloads {"user":"...","pass":"..."}
    static Map<String,String> parseJson(String s) {
        Map<String,String> out = new HashMap<>();
        if (s==null) return out;
        // naive: find all "key":"value" pairs
        int idx=0; while (idx < s.length()){
            int q = s.indexOf('"', idx);
            if (q<0) break;
            int q2 = s.indexOf('"', q+1);
            if (q2<0) break;
            String key = s.substring(q+1, q2);
            int colon = s.indexOf(':', q2);
            if (colon<0) break;
            int vStart = s.indexOf('"', colon);
            if (vStart<0) break;
            int vEnd = s.indexOf('"', vStart+1);
            if (vEnd<0) break;
            String val = s.substring(vStart+1, vEnd);
            out.put(key, val);
            idx = vEnd+1;
        }
        return out;
    }

    static String safeGet(Map<String,String> m, String k){ return m.getOrDefault(k,"").trim(); }

    static String jsonMsg(String m){ return "{\"message\":\"" + escape(m) + "\"}"; }

    static String escape(String s){
        return s.replace("\\","\\\\").replace("\"","\\\"");
    }

    static void sendJSON(Response r, int code, String body) throws IOException {
        // used by wrap above
        r.exchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
        r.exchange.getResponseHeaders().add("Access-Control-Allow-Headers","Content-Type, Authorization");
        r.exchange.getResponseHeaders().add("Access-Control-Allow-Methods","GET,POST,DELETE,OPTIONS");
        r.exchange.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        r.exchange.sendResponseHeaders(code, b.length);
        OutputStream os = r.exchange.getResponseBody();
        os.write(b);
        os.close();
    }

    static Session authSession(HttpExchange ex) throws Exception {
        String auth = ex.getRequestHeaders().getFirst("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) return null;
        String token = auth.substring(7);
        Session s = sessions.get(token);
        if (s==null) return null;
        if (s.exp < Instant.now().getEpochSecond()) { sessions.remove(token); return null; }
        return s;
    }

    // wrapper to adapt HttpHandler to our lambda style and centralize CORS/OPTIONS handling
    interface Handler { void handle(HttpExchange req, Response res) throws Exception; }
    static HttpHandler wrap(Handler h) {
        return exchange -> {
            if ("OPTIONS".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers","Content-Type, Authorization");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods","GET,POST,DELETE,OPTIONS");
                exchange.sendResponseHeaders(204, -1);
                exchange.close();
                return;
            }
            try {
                Response r = new Response(exchange);
                h.handle(exchange, r);
            } catch (Exception ex) {
                ex.printStackTrace();
                String msg = jsonMsg("internal error");
                exchange.getResponseHeaders().add("Access-Control-Allow-Origin","*");
                exchange.getResponseHeaders().add("Access-Control-Allow-Headers","Content-Type, Authorization");
                exchange.getResponseHeaders().add("Access-Control-Allow-Methods","GET,POST,DELETE,OPTIONS");
                byte[] b = msg.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");
                exchange.sendResponseHeaders(500, b.length);
                OutputStream os = exchange.getResponseBody();
                os.write(b); os.close();
            }
        };
    }
    static class Response { HttpExchange exchange; Response(HttpExchange e){ exchange=e; } }
}
