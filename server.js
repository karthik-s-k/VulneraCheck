const mongoose = require("mongoose");
const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt-nodejs");
const flash = require("connect-flash");
const session = require("express-session");
const bodyParser = require("body-parser");
const mime = require("mime");
require("dotenv").config();

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

mongoose
  .connect(process.env.DATABASE_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB", err);
  });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

userSchema.methods.generateHash = function (password) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(8), null);
};

userSchema.methods.validPassword = function (password, callback) {
  bcrypt.compare(password, this.password, function (err, isMatch) {
    if (err) {
      return callback(err);
    }
    callback(null, isMatch);
  });
};

const User = mongoose.model("User", userSchema);

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (email, password, done) => {
      User.findOne({ email: email })
        .then((user) => {
          if (!user) {
            return done(null, false, { message: "Incorrect email." });
          }
          user.validPassword(password, (err, isMatch) => {
            if (err) {
              return done(err);
            }
            if (!isMatch) {
              return done(null, false, { message: "Incorrect password." });
            }
            return done(null, user);
          });
        })
        .catch((err) => {
          done(err);
        });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err);
    });
});

app.get("/login.css", function (req, res) {
  res.setHeader("Content-Type", mime.getType("public/login.css"));
  res.sendFile(__dirname + "/public/login.css");
});

app.get("/register.css", function (req, res) {
  res.setHeader("Content-Type", mime.getType("public/register.css"));
  res.sendFile(__dirname + "/public/register.css");
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/dashboard",
    failureFlash: true,
  }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(__dirname + "/public/dashboard.html");
  } else {
    res.redirect("/");
  }
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/public/register.html");
});

app.post("/register", (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email })
    .then((user) => {
      if (user) {
        return res.send("User already exists");
      } else {
        const newUser = new User();
        newUser.name = name;
        newUser.email = email;
        newUser.password = newUser.generateHash(password);
        newUser.save().then(() => {
          return res.redirect("/");
        });
      }
    })
    .catch((err) => {
      throw err;
    });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
