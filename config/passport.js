var passport = require('passport'),
LocalStrategy = require('passport-local').Strategy,
TwitterStrategy = require('passport-twitter').Strategy,
GitHubStrategy = require('passport-github').Strategy,
bcrypt = require('bcrypt');

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findOne({ id: id } , function (err, user) {
        done(err, user);
    });
});

var oAuthCallback = function(token, tokenSecret, profile, done) {
    
    User.findOne({ uid: profile.id, provider: profile.provider }, function(err, user) {
    
      if (user) {
        return done(null, user);
      } else {

        var data = {
          provider: profile.provider,
          uid: profile.id,
          username: profile.username
        };

        var shortid = require('shortid'),
            generatePassword = require('password-generator');

        //Let's generate a fake email and a fake password to match the User model attributes    
        var fakeEmail = 'fake_' + new Date().getTime() + '_' + shortid.generate() + '@fake.com';
            data.email = fakeEmail;

        var password = generatePassword(12, false); 
            data.password = password;         

        User.create(data, function(err, user) {
          if (err) { return done(err); }
          return done(null, user, {
            message: 'Logged In Successfully'
          });
        });
      }
    });
  };

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  function(email, password, done) {
    User.findOne({ email: email }, function (err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect email.' });
      }
      bcrypt.compare(password, user.password, function (err, res) {
          if (!res){
            return done(null, false, {
              message: 'Invalid Password'
            });
          }
          var returnUser = {
            username: user.username,
            createdAt: user.createdAt,
            id: user.id
          };
          return done(null, returnUser, {
            message: 'Logged In Successfully'
          });
        });
    });
  }
));

passport.use(new TwitterStrategy({
    consumerKey: 'KCfKR5Snz7P6fSrk3XzCUbbjc',
    consumerSecret: '0FsA672nHMd8JRGEf8NvxwoLRN0h42IZ7rrso4ZnYXPTWz9VMG',
    callbackURL: "http://www.gitlist.io/auth/twitter/callback"
  },
  oAuthCallback
));

passport.use(new GitHubStrategy({
    clientID: '8d615f22f5453dfdce29',
    clientSecret: '730515f8fb48b9637330bc79987f0af98266f0e8',
    callbackURL: "http://www.gitlist.io/auth/github/callback"
  },
  oAuthCallback
));