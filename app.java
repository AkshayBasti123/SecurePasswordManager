import static spark.Spark.*;

import com.google.gson.Gson;
import org.mindrot.jbcrypt.BCrypt;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class app {

    // --- In-memory "DB" (demo) ---
    static class User {
        String username;
        String passwordHash;     // bcrypt
        byte[] pbkdf2Salt;       // for deriving AES key
        User(String u, String h, byte[] s) { username=u; passwordHash=h; pbkdf2Salt=s; }
    }

    static class Entry {
        String id;
        String site;
        String account;       // username/email for that site
        String ivB64;         // AES-GCM IV (12 bytes)
        String ctB64;         // ciphertext (includes GCM tag)
        Entry(String id, String site, String account, String ivB64, String ctB64) {
            this.id=id; this.site=site; this.account=account; this.ivB64=ivB64; this.ctB64=ctB64;
        }
    }

    static Map<String, User> users = new ConcurrentHashMap<>();         // username -> User
    static Map<String, List<Entry>> vault = new ConcurrentHashMap<>();  // username -> entries

    // --- JWT + session (we keep a server-side session so we can retain derived AES key) ---
    static class Session {
        String username;
        byte[] aesKey;       // per-user derived AES key (from their password via PBKDF2)
        long exp;            // epoch seconds
        Session(String u, byte[] k, long e){ username=u; aesKey=k; exp=e; }
    }

    static Map<String, Session> sessions = new ConcurrentHashMap<>(); // jti -> Session
    static final byte[] JWT_SECRET = new byte[32];  // HS256 secret
    static final SecureRandom RNG = new SecureRandom();
    static final Gson gson = new Gson();

    // --- Helpers: base64url (no padding) ---
    static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
    static byte[] db64url(String s) {
        return Base64.getUrlDecoder().decode(s);
    }

    // --- Minimal JWT (HS256) ---
    static String signJWT(String username, String jti, long expEpochSec) throws Exception {
        String header = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = b64url(("{\"sub\":\""+username+"\",\"exp\":"+expEpochSec+",\"jti\":\""+jti+"\"}")
                .getBytes(StandardCharsets.UTF_8));
        String data = header + "." + payload;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(JWT_SECRET, "HmacSHA256"));
        String sig = b64url(mac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        return data + "." + sig;
    }

    static class JwtParsed {
        String username; long exp; String jti;
    }

    static JwtParsed verifyJWT(String token) throws Exception {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;
        String data = parts[0] + "." + parts[1];

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(JWT_SECRET, "HmacSHA256"));
        byte[] expected = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        byte[] got = db64url(parts[2]);
        if (!MessageDigestIsEqual(expected, got)) return null;

        String payloadJson = new String(db64url(parts[1]), StandardCharsets.UTF_8);
        Map<?,?> map = gson.fromJson(payloadJson, Map.class);
        String sub = (String) map.get("sub");
        Double expD = (Double) map.get("exp");
        String jti = (String) map.get("jti");
        long exp = expD.longValue();

        if (Instant.now().getEpochSecond() > exp) return null;

        // must exist in session and not expired
        Session sess = sessions.get(jti);
        if (sess == null || sess.exp < Instant.now().getEpochSecond()) return null;

        JwtParsed p = new JwtParsed();
        p.username = sub; p.exp = exp; p.jti = jti;
        return p;
    }

    // constant-time compare
    static boolean MessageDigestIsEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int res = 0;
        for (int i=0;i<a.length;i++) res |= a[i] ^ b[i];
        return res == 0;
    }

    // --- PBKDF2 (derive per-user AES key from password) ---
    static byte[] deriveAESKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 120000, 256); // 120k iters, 256-bit key
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return keyBytes;
    }

    // --- AES-GCM encrypt/decrypt ---
    static class EncResult { byte[] iv; byte[] ct; }
    static EncResult aesGcmEncrypt(byte[] key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);
        EncResult r = new EncResult(); r.iv=iv; r.ct=ct; return r;
    }
    static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ct) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

    public static void main(String[] args) throws Exception {
        RNG.nextBytes(JWT_SECRET);
        port(8080);
        after((req, res) -> {
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            res.header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
            res.type("application/json");
        });
        options("/*", (req,res)->"");

        // --- Routes ---

        // Register
        post("/register", (req, res) -> {
            Map<?,?> data = gson.fromJson(req.body(), Map.class);
            String user = ((String)data.get("user")).trim();
            String pass = (String)data.get("pass");
            if (user.isEmpty() || pass == null || pass.length()<6) {
                res.status(400); return jsonMsg("Username & 6+ char password required");
            }
            if (users.containsKey(user)) { res.status(400); return jsonMsg("User exists"); }
            byte[] salt = new byte[16]; RNG.nextBytes(salt);
            String hash = BCrypt.hashpw(pass, BCrypt.gensalt(12));
            users.put(user, new User(user, hash, salt));
            vault.put(user, new ArrayList<>());
            return jsonMsg("Registered");
        });

        // Login -> issues JWT and stores session with derived AES key
        post("/login", (req, res) -> {
            Map<?,?> data = gson.fromJson(req.body(), Map.class);
            String user = ((String)data.get("user"));
            String pass = (String)data.get("pass");
            User u = users.get(user);
            if (u==null || !BCrypt.checkpw(pass, u.passwordHash)) {
                res.status(401); return jsonMsg("Invalid credentials");
            }
            byte[] aesKey = deriveAESKey(pass.toCharArray(), u.pbkdf2Salt);
            String jti = UUID.randomUUID().toString();
            long exp = Instant.now().getEpochSecond() + 60L*30; // 30 min
            sessions.put(jti, new Session(user, aesKey, exp));
            String token = signJWT(user, jti, exp);
            Map<String,Object> resp = new HashMap<>();
            resp.put("token", token);
            resp.put("user", user);
            return gson.toJson(resp);
        });

        // Add entry (encrypts password)
        post("/passwords", (req, res) -> {
            Session sess = requireAuth(req.headers("Authorization"));
            if (sess==null){ res.status(401); return jsonMsg("Unauthorized"); }
            Map<?,?> data = gson.fromJson(req.body(), Map.class);
            String site = ((String)data.get("site")).trim();
            String account = ((String)data.get("account")).trim();
            String secret = (String)data.get("secret");

            if (site.isEmpty() || account.isEmpty() || secret==null || secret.isEmpty()) {
                res.status(400); return jsonMsg("site, account, secret required");
            }
            EncResult enc = aesGcmEncrypt(sess.aesKey, secret.getBytes(StandardCharsets.UTF_8));
            Entry e = new Entry(UUID.randomUUID().toString(), site, account, b64url(enc.iv), b64url(enc.ct));
            vault.get(sess.username).add(e);
            return gson.toJson(e);
        });

        // List entries (decrypted for display)
        get("/passwords", (req, res) -> {
            Session sess = requireAuth(req.headers("Authorization"));
            if (sess==null){ res.status(401); return jsonMsg("Unauthorized"); }
            List<Entry> list = vault.getOrDefault(sess.username, new ArrayList<>());
            List<Map<String,String>> out = new ArrayList<>();
            for (Entry e : list) {
                String plain = new String(aesGcmDecrypt(sess.aesKey, db64url(e.ivB64), db64url(e.ctB64)), StandardCharsets.UTF_8);
                Map<String,String> row = new LinkedHashMap<>();
                row.put("id", e.id);
                row.put("site", e.site);
                row.put("account", e.account);
                row.put("secret", plain);
                out.add(row);
            }
            return gson.toJson(out);
        });

        // Delete entry
        delete("/passwords/:id", (req,res)->{
            Session sess = requireAuth(req.headers("Authorization"));
            if (sess==null){ res.status(401); return jsonMsg("Unauthorized"); }
            String id = req.params(":id");
            List<Entry> list = vault.getOrDefault(sess.username, new ArrayList<>());
            boolean removed = list.removeIf(e -> e.id.equals(id));
            return jsonMsg(removed ? "Deleted" : "Not found");
        });

        // Logout (invalidate session)
        post("/logout", (req,res)->{
            String auth = req.headers("Authorization");
            String token = (auth!=null && auth.startsWith("Bearer ")) ? auth.substring(7) : null;
            if (token!=null) {
                JwtParsed p = verifyJWT(token);
                if (p!=null) sessions.remove(p.jti);
            }
            return jsonMsg("Logged out");
        });

        // Health
        get("/health", (req,res)-> "{\"ok\":true}");
    }

    static Session requireAuth(String authHeader) throws Exception {
        if (authHeader==null || !authHeader.startsWith("Bearer ")) return null;
        String token = authHeader.substring(7);
        JwtParsed p = verifyJWT(token);
        if (p==null) return null;
        return sessions.get(p.jti);
    }

    static String jsonMsg(String m){
        return "{\"message\":\""+m.replace("\"","\\\"")+"\"}";
    }
}
