const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcryptjs");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
//console.log("Variables de entorno cargadas:", process.env);

const pool = new Pool({
  user: "odinstudent",
  host: "localhost",
  database: "authentication_exercise",
  password: "kintarap",
  port: 5432,
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

/*app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});*/
app.get("/", async (req, res) => {
  try {
    const { rows: posts } = await pool.query(`
          SELECT p.id, p.title, p.content, p.created_at, u.first_name, u.last_name
          FROM posts p
          JOIN users u ON p.author_id = u.id
          ORDER BY p.created_at DESC
      `);
    res.render("index", { user: req.user, posts: posts, error: null }); // Pass 'error' as null initially
  } catch (err) {
    console.error(err);
    res.render("index", {
      user: req.user,
      posts: [],
      error: "Failed to load posts.",
    });
  }
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  const { first_name, last_name, username, password, confirmPassword } =
    req.body;

  if (password !== confirmPassword) {
    return res.render("sign-up-form", { error: "Passwords do not match" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (first_name, last_name, username, password_hash, membership_status) VALUES ($1, $2, $3, $4, $5)",
      [first_name, last_name, username, hashedPassword, true] // Set membership_status to true
    );
    res.redirect("/"); // Redirect to the login page after successful registration
  } catch (err) {
    console.error(err);
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

app.post("/new-post", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/"); // Redirect if not logged in
  }

  const { title, content } = req.body;
  const author_id = req.user.id; // Get the ID of the logged-in user

  try {
    await pool.query(
      "INSERT INTO posts (title, content, author_id) VALUES ($1, $2, $3)",
      [title, content, author_id]
    );
    res.redirect("/"); // Redirect back to the home page after creating the post
  } catch (err) {
    console.error(err);
    res.render("index", {
      user: req.user,
      posts: [],
      error: "Failed to create new post.",
    });
  }
});

app.listen(3000, () => console.log("app listening on port 3000!"));
