// JWT.js
const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3100;

app.use(express.json());
app.use(cors());

// === 金鑰載入與產生 ===
let publicKey, privateKey;
const pubPath = path.join(__dirname, "public_key.pem");
const privPath = path.join(__dirname, "private_key.pem");

if (fs.existsSync(pubPath) && fs.existsSync(privPath)) {
  publicKey = fs.readFileSync(pubPath, "utf8");
  privateKey = fs.readFileSync(privPath, "utf8");
} else {
  const keyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  publicKey = keyPair.publicKey;
  privateKey = keyPair.privateKey;
  fs.writeFileSync(pubPath, publicKey);
  fs.writeFileSync(privPath, privateKey);
}

// === AES 包裝私鑰（記憶體加密）===
const aesKey = crypto.randomBytes(32);
const aesIv = crypto.randomBytes(16);

const wrapPrivateKey = () => {
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, aesIv);
  let encrypted = cipher.update(privateKey, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { wrappedKey: encrypted, iv: aesIv.toString("base64") };
};

const unwrapPrivateKey = ({ wrappedKey, iv }) => {
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, Buffer.from(iv, "base64"));
  let decrypted = decipher.update(wrappedKey, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

const wrappedPrivateKeyObj = wrapPrivateKey();

// === JWT 簽發 API ===
app.post("/sign", (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== "object") {
    return res.status(400).json({ error: "payload 無效" });
  }

  const token = jwt.sign(payload, unwrapPrivateKey(wrappedPrivateKeyObj), {
    algorithm: "RS256",
    expiresIn: "3min",
  });

  return res.json({ token });
});

// === JWT 驗證 API ===
app.post("/verify", (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    return res.json({ valid: true, payload: decoded });
  } catch (err) {
    return res.status(401).json({ valid: false, error: err.message });
  }
});

app.listen(PORT, "0.0.0.0", () => console.log(`伺服器啟動於 PORT: ${PORT}`));

