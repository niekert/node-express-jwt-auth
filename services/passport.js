const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
  User.findOne({ email: email }, function (err, user) {
    if (err) { return done(err); }

    if (!user) { return done(null, false); }

    console.log('my user', user);
    user.comparePassword(password, function (err, isMatch) {
      return done(err, isMatch ? user : false);
    });
  });
});

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret,
};

const jwtLogin = new JwtStrategy(jwtOptions, function (payload, done) {
  //Only callback if the user exists in the database
  User.findById(payload.sub, function (err, user) {
    if (err) { return done(err, false); }

    done(null, user ? user : false);
  });
});

passport.use(jwtLogin);
passport.use(localLogin);
