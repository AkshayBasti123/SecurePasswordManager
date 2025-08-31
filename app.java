
// Simple backend with Java Spark framework (tiny, no config needed)
import static spark.Spark.*;
import com.google.gson.Gson;
import org.mindrot.jbcrypt.BCrypt;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.*;

public class app {
    private static Map<String, String> users = new HashMap<>(); // username -> hashed password
    private static Map<String, List<String>> vault = new HashMap<>(); // username -> encrypted passwords
    private static SecretKey aesKey;
    private static Gson gson = new Gson();

    public static void main(String[] args) throws Exception {
        port(8080);

        // Generate AES key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        aesKey = keyGen.generateKey();

        post("/register", (req, res) -> {
            Map<String, String> data = gson.fromJson(req.body(), Map.class);
            String user = data.get("user");
            String pass = data.get("pass");

            if (users.containsKey(user)) {
                res.status(400);
                return "User already exists";
            }

            String hashed = BCrypt.hashpw(pass, BCrypt.gensalt());
            users.put(user, hashed);
            vault.put(user, new ArrayList<>());
            return "Registered!";
        });

        post("/login", (req, res) -> {
            Map<String, String> data = gson.fromJson(req.body(), Map.class);
            String user = data.get("user");
            String pass = data.get("pass");

            if (users.containsKey(user) && BCrypt.checkpw(pass, users.get(user))) {
                return "OK";
            }
            res.status(401);
            return "Invalid login";
        });

        post("/save", (req, res) -> {
            Map<String, String> data = gson.fromJson(req.body(), Map.class);
            String user = data.get("user");
            String entry = data.get("entry");

            String encrypted = encrypt(entry);
            vault.get(user).add(encrypted);
            return "Saved!";
        });

        get("/vault/:user", (req, res) -> {
            String user = req.params(":user");
            return gson.toJson(vault.getOrDefault(user, new ArrayList<>()));
        });
    }

    private static String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
}
