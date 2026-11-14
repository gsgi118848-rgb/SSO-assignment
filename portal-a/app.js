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
    name: "portalA.sid",
    secret: SESSION_SECRET || "dev-secret-portal-a",
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
  console.log("[학교포털 A] Issuer:", issuer.issuer);

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

  // 메인 페이지
  app.get("/", (req, res) => {
    res.render("index", { user: req.user });
  });

  // 로그인 시작
  app.get("/login", passport.authenticate("keycloak"));

  // Callback
  app.get(
    "/callback",
    passport.authenticate("keycloak", {
      failureRedirect: "/",
      successRedirect: "/dashboard",
    })
  );

  // 학교포털 주요 기능 (학사행정/성적/공지)
  app.get("/dashboard", ensureAuthenticated, (req, res) => {
    const academicData = {
      notices: [
        { id: 1, title: "[학사] 2026학년도 2학기 기말고사 일정 안내", date: "2026-11-10" },
        { id: 2, title: "[장학] 국가장학금 1차 신청 기간 공지", date: "2026-11-12" },
        { id: 3, title: "[시스템] 통합로그인(SSO) 기반 이러닝 연동 완료", date: "2026-11-14" },
      ],
      grades: [
        { subject: "컴퓨터구조", credit: 3, grade: "A+" },
        { subject: "정보보호개론", credit: 3, grade: "A0" },
        { subject: "운영체제", credit: 3, grade: "A+" },
      ],
    };
    res.render("dashboard", { user: req.user, academicData });
  });

  // 학생 프로필
  app.get("/profile", ensureAuthenticated, (req, res) => {
    res.render("profile", { user: req.user });
  });

  // 통합 로그아웃 (Single Logout)
  app.get("/logout", ensureAuthenticated, (req, res) => {
    const idToken = req.user?.tokens?.id_token;
    const endSessionUrl = issuer.metadata.end_session_endpoint;

    req.logout(() => {
      req.session.destroy(() => {
        res.clearCookie("portalA.sid", {
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

  app.listen(PORT, () => console.log(`학교포털(서비스 A) 실행 중: http://localhost:${PORT}`));
}

setupAuth().catch((err) => console.error("Auth error:", err));