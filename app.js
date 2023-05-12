
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false

}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-sadiq:mariam440@cluster0.fzqz2pj.mongodb.net/userDB");

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user.id)
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/auth/facebook",
  passport.authenticate("facebook")
  );

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect("/secrets");
    });

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/secrets", function(req, res){
User.find({"secret": {$ne: null}}).then(function(foundUser){
  res.render("secrets", {userWithSecrets: foundUser});
});
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout(function(err){
    if(err){
      console.log(err);
    } else {
        res.redirect("/");
    }
  });
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user).then(function(foundUser){
    if (foundUser){
      foundUser.secret = submittedSecret;
      foundUser.save().then(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/register", function(req, res){
User.register({username: req.body.username}, req.body.password, function(err, user){
  if(err){
    console.log(err);
    res.redirect("/register");
  } else {
    passport.authenticate("local")(req, res, function(){
      res.redirect("/secrets");
    });
  }
});
});

app.post("/login", function(req, res){
  const user = new User ({
    username: req.body.username,
    passport: req.body.passport
  });
  req.login(user, function(err){
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

let port = process.env.PORT;
if(port == null || port == ""){
  port = 3000;
}

app.listen(port, function(req, res){
  console.log("Server started in port 3000");
});
