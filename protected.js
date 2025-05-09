// protected_server.js
const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 3300;

// 載入 publicKey 用來驗證 RS256 的 JWT
const publicKey = fs.readFileSync(
  path.join(__dirname, "public_key.pem"),
  "utf8"
);

// 解析 Cookie
app.use(cookieParser());

// 防止快取
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  next();
});

// JWT 驗證中介層
const requireAuth = (req, res, next) => {
  const token = req.cookies.jwt;
  if (!token) return res.status(401).send("未授權：缺少 JWT");

  try {
    const payload = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

    if (payload.dest !== "http://localhost:3300/protected/profile.html") {
      return res.status(403).send("拒絕存取：dest 欄位不符");
    }

    next();
  } catch (err) {
    console.error("JWT 驗證失敗：", err.message);
    return res.status(401).send("JWT 驗證失敗");
  }
};

// 掛載保護頁面靜態路由（必須先通過驗證）
app.use(
  "/protected",
  requireAuth,
  express.static(path.join(__dirname, "protected"))
);

// 預設路由
app.get("/", (req, res) => {
  res.send("這是保護頁面服務器，請透過正確驗證訪問 /protected");
});

app.get("/api/profile-info", (req, res) => {
  const token = req.cookies.jwt;
  try {
    const payload = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    return res.json({
      jwt: token,
      payload,
    });
  } catch (err) {
    return res.status(401).json({ error: "驗證失敗" });
  }
});

app.post("/logout", (req, res) => {
  res.clearCookie("jwt", { httpOnly: true, secure: false, sameSite: "strict" });
  return res.json({ message: "登出成功" });
});

// 啟動伺服器
app.listen(PORT, () => {
  console.log(`✅ Protected server running on http://localhost:${PORT}`);
});
