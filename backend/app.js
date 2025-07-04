require('dotenv').config();
const secret = process.env.SESSION_SECRET;
const GitHubStrategy = require('passport-github2').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const express = require("express");
const path = require("path");
const session = require('express-session');
const passport = require('passport');
const fs = require('fs');
const FileStore = require('session-file-store')(session);

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  store: new FileStore({}),
  secret: secret,
  resave: false,
  saveUninitialized: false
}));
app.set("views", path.resolve("./views"));
// Serve static files from current folder
app.use(express.static(__dirname));
app.set("view engine", "ejs");

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: "http://localhost:3001/auth/github/callback"
}, function(accessToken, refreshToken, profile, done) {
  // Save user info to notes.json if not already present
  const userData = {
    id: profile.id,
    username: profile.username,
    displayName: profile.displayName,
    emails: profile.emails,
    provider: profile.provider
  };
  fs.readFile('notes.json', 'utf8', (err, data) => {
    let notes = [];
    if (!err && data) {
      try { notes = JSON.parse(data); } catch (e) { notes = []; }
    }
    // Only add if user not already present
    if (!notes.find(u => u.id === userData.id && u.provider === userData.provider)) {
      notes.push(userData);
      fs.writeFile('notes.json', JSON.stringify(notes, null, 2), () => {});
    }
  });
  return done(null, profile);
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
function(accessToken, refreshToken, profile, done) {
  // Save user info to notes.json if not already present
  const userData = {
    id: profile.id,
    username: profile.displayName || profile.username || null,
    displayName: profile.displayName,
    emails: profile.emails,
    provider: profile.provider
  };
  fs.readFile('notes.json', 'utf8', (err, data) => {
    let notes = [];
    if (!err && data) {
      try { notes = JSON.parse(data); } catch (e) { notes = []; }
    }
    // Only add if user not already present
    if (!notes.find(u => u.id === userData.id && u.provider === userData.provider)) {
      notes.push(userData);
      fs.writeFile('notes.json', JSON.stringify(notes, null, 2), () => {});
    }
  });
  return done(null, profile);
}
));

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.redirect('/'); // or redirect to your login page
}

app.get('/', (req, res) => {
  res.render('auth/login');
});

app.get('/contact', (req, res) => {
  res.render('auth/contact');
});

app.get('/index', (req, res) => {
  res.render('auth/index');
});

app.get('/register', (req, res) => {
  res.render('auth/register');
});

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] })
);

app.get('/auth/github/callback', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/index');
  }
);

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {

    res.redirect('/index');
  }
);

app.post('/register', (req, res) => {
  const { email, password, firstName, lastName, phone, gender, location } = req.body;
  const userData = {
    id: email, // Use email as unique ID for local registration
    username: email,
    displayName: `${firstName} ${lastName}`,
    emails: [{ value: email }],
    provider: 'local',
    phone,
    gender,
    location,
    password
  };

  fs.readFile('notes.json', 'utf8', (err, data) => {
    let notes = [];
    if (!err && data) {
      try { notes = JSON.parse(data); } catch (e) { notes = []; }
    }
    // Only add if user not already present
    if (!notes.find(u => u.id === userData.id && u.provider === userData.provider)) {
      notes.push(userData);
      fs.writeFile('notes.json', JSON.stringify(notes, null, 2), () => {});
    }
  });

  // Redirect or render a success page
  res.redirect('/index');
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  fs.readFile('notes.json', 'utf8', (err, data) => {
    let users = [];
    if (!err && data) {
      try { users = JSON.parse(data); } catch (e) { users = []; }
    }
    // Debug: log users and incoming credentials
    console.log('Login attempt:', email, password);
    console.log('Users:', users);
    // Find local user (manual registration)
    const user = users.find(u =>
      u.provider === 'local' &&
      u.emails && u.emails[0] &&
      u.emails[0].value === email
    );
    if (!user) {
      return res.status(401).json({ message: 'No such user registered.' });
    }
    if (!user.password) {
      return res.status(401).json({ message: 'This user was registered before password saving was enabled. Please register again.' });
    }
    if (user.password !== password) {
      return res.status(401).json({ message: 'Invalid password.' });
    }
    res.status(200).json({ message: 'Login successful' });
  });
});

module.exports = app;
