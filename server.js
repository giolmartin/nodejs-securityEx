//npm init for package.json
//npm install express

// npm install passport // passport-google-oauth20

const fs = require('fs');
const path = require('path');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');

require('dotenv').config();

const PORT = process.env.PORT || 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
  callbackURL: '/auth/google/callback',
};

function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log('Google profile', profile);
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// Save temporary user data in the session
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Retrieve the user data from the session
passport.deserializeUser((obj, done) => {
  // User.findById(id).then(user = {
  //     done(null, user);
  // });
  done(null, obj);
});

const app = express();

app.use(helmet());

app.use(
  cookieSession({
    name: 'session',
    maxAge: 30 * 24 * 60 * 60 * 1000,
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);
app.use(passport.initialize());
app.use(passport.session());

function checkLogIn(req, res, next) {
  console.log('Current user is: ', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user; //Checks if user is logged in
  if (!isLoggedIn) {
    return res.status(401).json({
      error: 'You must log in to access this resource',
    });
  }
  next();
}

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }),
  (req, res) => {
    console.log('Google auth callback');
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout(); //Removes the user from the session
  return res.redirect('/'); //Redirects to home page
}); //TODO: implement logout

app.get('/secret', checkLogIn, (req, res) => {
  return res.send('Your secret value is 42!');
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/failure', (req, res) => {
  return res.send('Login failed');
});

https
  .createServer(
    {
      cert: fs.readFileSync('cert.pem'),
      key: fs.readFileSync('key.pem'),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Server started on port ${PORT}...`);
  });
