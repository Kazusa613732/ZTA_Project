const express = require("express");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

const PORT = 3000;
const app = express();

app.use(express.static("./public"));
app.use(express.json());
app.use(cookieParser());

// === RSA 金鑰持久化與生成 ===
let publicKey, privateKey;

if (fs.existsSync("./public_key.pem") && fs.existsSync("./private_key.pem")) {
  publicKey = fs.readFileSync("./public_key.pem", "utf8");
  privateKey = fs.readFileSync("./private_key.pem", "utf8");
} else {
  const keyPair = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "pkcs1", format: "pem" },
    privateKeyEncoding: { type: "pkcs1", format: "pem" },
  });
  publicKey = keyPair.publicKey;
  privateKey = keyPair.privateKey;
  fs.writeFileSync("./public_key.pem", publicKey);
  fs.writeFileSync("./private_key.pem", privateKey);
}

// === AES 包裝私鑰 ===
const aesKey = crypto.randomBytes(32);
const aesIv = crypto.randomBytes(16);

const wrapPrivateKey = () => {
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, aesIv);
  let encrypted = cipher.update(privateKey, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { wrappedKey: encrypted, iv: aesIv.toString("base64") };
};

const unwrapPrivateKey = ({ wrappedKey, iv }) => {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    aesKey,
    Buffer.from(iv, "base64")
  );
  let decrypted = decipher.update(wrappedKey, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

const wrappedPrivateKeyObj = wrapPrivateKey();
const getPrivateKey = () => unwrapPrivateKey(wrappedPrivateKeyObj);
const getPublicKey = () => publicKey;

const userStore = {};
const challengeStore = {};

app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  next();
});

// === 註冊 ===
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (Object.values(userStore).some((u) => u.username === username)) {
    return res.status(400).json({ error: "使用者名稱已存在。" });
  }
  const id = `user_${Date.now()}`;
  const user = { id, username, password };
  userStore[id] = user;
  return res.json({ id });
});

// === 檢查使用者是否存在 ===
app.post("/check-user", (req, res) => {
  const { username } = req.body;
  const exists = Object.values(userStore).some((u) => u.username === username);
  return res.json({ exists });
});

// === FIDO2 註冊挑戰 ===
app.post("/register-challenge", async (req, res) => {
  const { username } = req.body;
  const user = Object.values(userStore).find((u) => u.username === username);
  if (!user) return res.status(404).json({ error: "找不到使用者" });

  const challengePayload = await generateRegistrationOptions({
    rpID: "localhost",
    rpName: "本地伺服器",
    attestationType: "none",
    userName: user.username,
    timeout: 30000,
  });

  challengeStore[username] = challengePayload.challenge;
  return res.json({ options: challengePayload });
});

// === FIDO2 註冊驗證 ===
app.post("/register-verify", async (req, res) => {
  const { username, cred } = req.body;
  const user = Object.values(userStore).find((u) => u.username === username);
  if (!user) return res.status(404).json({ error: "找不到使用者" });

  const challenge = challengeStore[username];
  const result = await verifyRegistrationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
  });

  if (!result.verified) return res.status(400).json({ error: "註冊失敗" });
  user.passkey = result.registrationInfo;
  return res.json({ verified: true });
});

// === FIDO2 登入挑戰 ===
app.post("/login-challenge", async (req, res) => {
  const { username } = req.body;
  const user = Object.values(userStore).find((u) => u.username === username);
  if (!user) return res.status(404).json({ error: "找不到使用者" });

  const options = await generateAuthenticationOptions({ rpID: "localhost" });
  challengeStore[username] = options.challenge;
  return res.json({ options });
});

// === FIDO2 登入驗證 ===
app.post("/login-verify", async (req, res) => {
  const { username, cred } = req.body;
  const user = Object.values(userStore).find((u) => u.username === username);
  if (!user) return res.status(404).json({ error: "找不到使用者" });

  const challenge = challengeStore[username];
  const result = await verifyAuthenticationResponse({
    expectedChallenge: challenge,
    expectedOrigin: "http://localhost:3000",
    expectedRPID: "localhost",
    response: cred,
    authenticator: user.passkey,
  });

  if (!result.verified) return res.status(400).json({ error: "驗證失敗" });

  const token = jwt.sign(
    {
      username: user.username,
      dest: "http://localhost:3300/protected/profile.html",
    },
    getPrivateKey(),
    {
      algorithm: "RS256",
      expiresIn: "3min",
    }
  );

  res.cookie("jwt", token, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 3 * 60 * 1000,
  });

  return res.json({ success: true });
});

// === 登出 ===
app.post("/logout", (req, res) => {
  res.clearCookie("jwt", { httpOnly: true, secure: false, sameSite: "strict" });
  return res.json({ message: "登出成功" });
});

// === JWT 驗證 & 公開資訊回傳（測試用） ===
app.get("/api/profile-info", (req, res) => {
  const token = req.cookies.jwt;
  try {
    jwt.verify(token, getPublicKey(), { algorithms: ["RS256"] });
    return res.json({
      jwt: token,
      wrappedKey: wrappedPrivateKeyObj,
      publicKey: getPublicKey(),
      privateKey: getPrivateKey(), // 用於 jwt.io 驗證
    });
  } catch (err) {
    return res.status(401).json({ error: "驗證失敗" });
  }
});

app.listen(PORT, () => console.log(`伺服器啟動於 PORT: ${PORT}`));
