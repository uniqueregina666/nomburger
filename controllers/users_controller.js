var bcrypt = require('bcryptjs');
var models = require('../models');
var express = require('express');
var router = express.Router();

//this is the users_controller.js file
router.get('/new', function (req, res) {
    res.render('users/new');
});

router.get('/sign-in', function (req, res) {
    res.render('users/sign_in');
});

router.get('/sign-out', function (req, res) {
    req.session.destroy(function (err) {
        res.redirect('/')
    })
});


// login
router.post('/login', function (req, res) {
    models.User.findOne({
        where: { email: req.body.email }
    }).then(function (user) {

        if (user == null) {
            res.redirect('/users/sign-in')
        }

    
        bcrypt.compare(req.body.password, user.password_hash, function (err, result) {
            // if the result is true (and thus pass and hash match)
            if (result == true) {

               
                // we save the logged in status to the session
                req.session.logged_in = true;
                // the username to the session
                req.session.username = user.username;
                // the user id to the session
                req.session.user_id = user.id;
                // and the user's email.
                req.session.user_email = user.email;

                res.redirect('/');
            }
            // if the result is anything but true (password invalid)
            else {
                // redirect user to sign in
                res.redirect('/users/sign-in')
            }
        });
    })
});


// register a user
router.post('/create', function (req, res) {
    models.User.findAll({
        where: { email: req.body.email }
    }).then(function (users) {

        if (users.length > 0) {
            console.log(users)
            res.send('we already have an email or username for this account')
        } else {


            bcrypt.genSalt(10, function (err, salt) {
                bcrypt.hash(req.body.password, salt, function (err, hash) {


                    models.User.create({
                        email: req.body.email,
                        password_hash: hash
                    })

                        .then(function (user) {




                            req.session.logged_in = true;

                            req.session.username = user.username;

                            req.session.user_id = user.id;

                            req.session.user_email = user.email;


                            res.redirect('/')
                        });
                });
            });

        }
    });
});

module.exports = router;