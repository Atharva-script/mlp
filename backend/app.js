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
const mongoose = require('mongoose');

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

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch((err) => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// User schema/model
const userSchema = new mongoose.Schema({
  id: { type: String, required: true },
  username: String,
  displayName: String,
  emails: [{ value: String }],
  provider: { type: String, required: true },
  avatar: String,
  phone: String,
  gender: String,
  location: String,
  password: String
});
const User = mongoose.model('User', userSchema);

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((obj, done) => {
  done(null, obj);
});
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL
}, async function(accessToken, refreshToken, profile, done) {
  try {
    const userData = {
      id: profile.id,
      username: profile.username,
      displayName: profile.displayName,
      emails: profile.emails,
      provider: profile.provider,
      avatar: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : undefined
    };
    // Upsert: create or update user by id+provider
    const user = await User.findOneAndUpdate(
      { id: userData.id, provider: userData.provider },
      { $set: userData },
      { new: true, upsert: true }
    );
    return done(null, user);
  } catch (err) {
    console.error('GitHubStrategy error:', err);
    return done(err, null);
  }
}));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async function(accessToken, refreshToken, profile, done) {
  try {
    const userData = {
      id: profile.id,
      username: profile.displayName || profile.username || null,
      displayName: profile.displayName,
      emails: profile.emails,
      provider: profile.provider,
      avatar: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : undefined
    };
    // Upsert: create or update user by id+provider
    const user = await User.findOneAndUpdate(
      { id: userData.id, provider: userData.provider },
      { $set: userData },
      { new: true, upsert: true }
    );
    return done(null, user);
  } catch (err) {
    console.error('GoogleStrategy error:', err);
    return done(err, null);
  }
}));

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

app.post('/register', async (req, res) => {
  const { email, password, firstName, lastName, phone, gender, location } = req.body;
  const userData = {
    id: email,
    username: email,
    displayName: `${firstName} ${lastName}`,
    emails: [{ value: email }],
    provider: 'local',
    phone,
    gender,
    location,
    password
  };
  try {
    let user = await User.findOne({ id: userData.id, provider: userData.provider });
    if (!user) {
      user = new User(userData);
      await user.save();
    }
    res.redirect('/index');
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).send('Registration failed');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({
      provider: 'local',
      'emails.0.value': email
    });
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
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

module.exports = app;
