const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");

const pool = new Pool({
  user: "odinstudent", // Reemplaza con tu nombre de usuario de PostgreSQL (debe ser string)
  host: "localhost",
  database: "authentication_exercise", // Reemplaza con el nombre de tu base de datos (debe ser string)
  password: "kintarap", // Reemplaza con tu contraseña de PostgreSQL (debe ser string)
  port: 5432, // El puerto predeterminado de PostgreSQL es 5432 (debe ser number)
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password_hash);

      if (!passwordMatch) {
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10); // El segundo argumento (10) es el "salt rounds"
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
      [req.body.username, hashedPassword]
    );
    res.redirect("/");
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

// Ruta para el cierre de sesión
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
