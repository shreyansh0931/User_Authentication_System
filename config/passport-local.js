// Importing required modules
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const User = require('../models/user');
const bcrypt = require('bcrypt');
const validator = require('validator');

// Authentication using passport
passport.use(
    'local',
    new localStrategy(
        {
            usernameField: 'email',
            passReqToCallback: true,
        },
        async function (req, email, password, done) {
            try {
                if (!validator.isEmail(email)) {
                    req.flash('error', 'Invalid email.');
                    return done(null, false);
                }

                let user = await User.findOne({ email: email })
                    .select('+password')
                    .exec();

                if (!user) {
                    req.flash('error', 'Invalid Username or Password!');
                    return done(null, false);
                }

                let matchPassword = await bcrypt.compare(password, user.password);

                if (!matchPassword) {
                    req.flash('error', 'Invalid Username or Password!');
                    return done(null, false);
                }

                return done(null, user);
            } catch (err) {
                console.log('Error in passport: ', err);
                return done(err);
            }
        }
    )
);

// Serialize user to decide which key to be kept in cookies
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

// Deserialize user to decide which key to be kept in cookies
passport.deserializeUser(async function (id, done) {
    try {
        let user = await User.findById(id).exec();
        return done(null, user);
    } catch (err) {
        console.log('Error in passport: ', err);
        return done(err);
    }
});

passport.checkAuthentication = function (req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/sign-in');
};

passport.setAuthenticatedUser = function (req, res, next) {
    if (req.isAuthenticated()) {
        res.locals.user = req.user;
    }
    return next();
};

module.exports = passport;
