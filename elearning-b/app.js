require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const { Issuer, Strategy } = require("openid-client");
const path = require("path");

const {
  PORT,
  SESSION_SECRET,
  KEYCLOAK_ISSUER,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  KEYCLOAK_CALLBACK_URL,
} = process.env;

const app = express();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    name: "elearningB.sid", // 서비스 B 전용 세션 쿠키
    secret: SESSION_SECRET || "dev-secret-elearning-b",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  res.redirect("/login");
}

async function setupAuth() {
  const issuer = await Issuer.discover(KEYCLOAK_ISSUER);
  console.log("[이러닝 B] Issuer:", issuer.issuer);

  const client = new issuer.Client({
    client_id: KEYCLOAK_CLIENT_ID,
    client_secret: KEYCLOAK_CLIENT_SECRET,
    redirect_uris: [KEYCLOAK_CALLBACK_URL],
    response_types: ["code"],
  });

  passport.use(
    "keycloak",
    new Strategy(
      {
        client,
        params: {
          scope: "openid profile email",
          kc_idp_hint: "google", 
        },
      },
      (tokenset, userinfo, done) => {
        const user = {
          id: userinfo.sub,
          username: userinfo.preferred_username,
          name: userinfo.name || userinfo.preferred_username,
          email: userinfo.email,
          picture: userinfo.picture,
          tokens: {
            id_token: tokenset.id_token,
          },
        };
        return done(null, user);
      }
    )
  );

  // 이러닝 메인
  app.get("/", (req, res) => {
    res.render("index", { user: req.user });
  });

  // 로그인 시작 (Keycloak 세션이 이미 있으면 입력창 없이 즉시 Callback으로 통과됨)
  app.get("/login", passport.authenticate("keycloak"));

  // Callback
  app.get(
    "/callback",
    passport.authenticate("keycloak", {
      failureRedirect: "/",
      successRedirect: "/courses",
    })
  );

  // 내 강의실 (수강 강좌, 진도율, 과제 현황)
  app.get("/courses", ensureAuthenticated, (req, res) => {
    const courseList = [
      {
        code: "CSE301",
        title: "정보보호개론 (Keycloak SSO 실습)",
        professor: "김보안 교수",
        progress: 92,
        assignment: "제출 완료",
      },
      {
        code: "CSE204",
        title: "컴퓨터구조",
        professor: "이아키 교수",
        progress: 85,
        assignment: "진행 중 (마감 D-3)",
      },
      {
        code: "CSE305",
        title: "운영체제",
        professor: "박커널 교수",
        progress: 100,
        assignment: "제출 완료",
      },
    ];
    res.render("courses", { user: req.user, courseList });
  });

  // 수강생 프로필
  app.get("/profile", ensureAuthenticated, (req, res) => {
    res.render("profile", { user: req.user });
  });

  // 통합 로그아웃
  app.get("/logout", ensureAuthenticated, (req, res) => {
    const idToken = req.user?.tokens?.id_token;
    const endSessionUrl = issuer.metadata.end_session_endpoint;

    req.logout(() => {
      req.session.destroy(() => {
        res.clearCookie("elearningB.sid", {
          path: "/",
          httpOnly: true,
          sameSite: "lax",
        });

        if (!endSessionUrl) return res.redirect("/");

        const redirect = encodeURIComponent(`http://localhost:${PORT}/`);
        let url =
          `${endSessionUrl}?post_logout_redirect_uri=${redirect}` +
          `&client_id=${KEYCLOAK_CLIENT_ID}`;

        if (idToken) url += `&id_token_hint=${idToken}`;
        return res.redirect(url);
      });
    });
  });

  app.listen(PORT, () => console.log(`이러닝(서비스 B) 실행 중: http://localhost:${PORT}`));
}

setupAuth().catch((err) => console.error("Auth error:", err));