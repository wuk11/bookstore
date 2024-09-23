const User = require('../models/user.js');
const bcrypt = require ('bcryptjs');
const crypto = require('crypto');
const {validationResult} = require('express-validator');
// const nodemailer = require('nodemailer');
const mailjet = require('node-mailjet')
    .apiConnect(
    'c436b4eb60960fa5cf15b872faf61c04',
    '44e8d889f4ec6c800bba7b54890b8262'
    );

// const transporter = nodemailer.createTransport(mailjet({

// }));

// const request = mailjet.post('send', { version: 'v3.1' }).request({
//     Messages: [
//       {
//         From: {
//           Email: 'vukasin.abv@gmail.com',
//           Name: 'Me',
//         },
//         To: [
//           {
//             Email: 'vukasin.abv@gmail.com',
//             Name: 'You',
//           },
//         ],
//         Subject: 'Email verification',
//         TextPart: 'Greetings from Shop.Localhost!',
//         HTMLPart:
//           '<h3>Welcome to <a href="http://localhost:3000/">Shop</a>!</h3><br />May the delivery force be with you!',
//       },
//     ],
//   })

exports.getLogin = (req, res, next) => {
    let message = req.flash('error');
    if(message.length > 0){
        message = message[0];
    }
    else{
        message = null;
    }

    // request
    //     .then(result => {
    //         console.log(result.body)
    //     })
    //     .catch(err => {
    //         console.log(err.statusCode)
    //     })

    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: message,
        oldInput: {
            email: "",
            password: ""
        },
        validationErrors: []
    });
}

exports.getSignup = (req, res, next) => {
    let message = req.flash('error');
    const errors = validationResult(req);
    if(message.length > 0){
        message = message[0];
    }
    else{
        message = null;
    }

    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        errorMessage: message,
        oldInput: {
            email: "",
            password: "",
            confirmPassword: ""
        },
        validationErrors: errors.array()
    });
}

exports.postLogin = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(422).render('auth/login', {
            path: '/login',
            pageTitle: 'Login',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email: email,
                password: password
            },
            validationErrors: errors.array()
        });
    }

    User.findOne({email: email})
        .then(user => {
            if(!user){
                return res.status(422).render('auth/login', {
                    path: '/login',
                    pageTitle: 'Login',
                    errorMessage: 'Invalid email or password.',
                    oldInput: {
                        email: email,
                        password: password
                    },
                    validationErrors: []
                });
            }
            bcrypt
                .compare(password, user.password)
                .then(doMatch => {
                    if(doMatch){
                        req.session.user = user;
                        req.session.isLoggedIn = true;
                        return req.session.save((err) => {
                            if(err){
                                console.log(err);
                            }
                            return res.redirect('/');
                        })
                    }
                    return res.status(422).render('auth/login', {
                        path: '/login',
                        pageTitle: 'Login',
                        errorMessage: 'Invalid email or password.',
                        oldInput: {
                            email: email,
                            password: password
                        },
                        validationErrors: []
                    });
                })
                .catch(err => {
                    console.log(err);
                    res.redirect('/login');
                });
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.postLogout = (req, res, next) => {
    req.session.destroy(() => {
        res.redirect('/');
    })
}

exports.postSignup = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);
    console.log(errors.array())
    if(!errors.isEmpty()){
        return res
                .status(422)
                .render('auth/signup', {
                    path: '/signup',
                    pageTitle: 'Signup',
                    errorMessage: errors.array()[0].msg,
                    oldInput: { email: email, password: password, confirmPassword: req.body.confirmPassword },
                    validationErrors: errors.array()
                });
    }
    bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
            const user = new User({
                email: email,
                password: hashedPassword,
                cart: { items: [] }
            })
            return user.save();
        })
        .then(result => {
            res.redirect('/login');
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.getReset = (req, res, next) => {
    let message = req.flash('error');
    if(message.length > 0){
        message = message[0];
    }
    else{
        message = null;
    }

    res.render('auth/reset', {
        path: '/reset',
        pageTitle: 'Reset Password',
        errorMessage: message
    });
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if(err){
            console.log(err);
            return res.redirect('/reset');
        }
        const token = buffer.toString('hex');
        User
            .findOne({email: req.body.email})
            .then(user => {
                if(!user){
                    req.flash('error', 'No account with that email found.');
                    return res.redirect('/reset');
                }
                user.resetToken = token;
                user.resetTokenExpiration = Date.now() + 3600000;
                return user.save();
            })
            .then(result => {
                res.redirect('/');
                mailjet
                    .post('send', { version: 'v3.1' })
                    .request({
                        Messages: [
                        {
                            From: {
                            Email: 'vukasin.abv@gmail.com',
                            Name: 'Shop',
                            },
                            To: [
                            {
                                Email: req.body.email,
                                Name: 'User',
                            },
                            ],
                            Subject: 'Reset Password',
                            TextPart: 'Greetings from Shop.Localhost!',
                            HTMLPart:
                            `<p>You requested a password reset.<p>
                            <p>Click here to reset your password: <a href="http://localhost:3000/reset/${token}">link</a><p>`,
                        },
                        ],
                    })
            })
            .catch(err => {
                const error = new Error(err);
                error.httpStatusCode = 500;
                return next(error);
            });
    })
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token;
    User
        .findOne({resetToken: token, resetTokenExpiration: {$gt: Date.now()}})
        .then(user => {
            let message = req.flash('error');
            if(message.length > 0){
                message = message[0];
            }
            else{
                message = null;
            }
        
            res.render('auth/new-password', {
                path: '/new-password',
                pageTitle: 'New Password',
                errorMessage: message,
                userId: user._id.toString(),
                passwordToken: token
            });
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password;
    const userId = req.body.userId;
    const passwordToken = req.body.passwordToken;
    let resetUser;

    User
        .findOne({resetToken: passwordToken, resetTokenExpiration: {$gt: Date.now()}, _id: userId})
        .then(user => {
            resetUser = user;
            return bcrypt.hash(newPassword, 12);
        })
        .then(hashedPassword => {
            resetUser.password = hashedPassword;
            resetUser.resetToken = null;
            resetUser.resetTokenExpiration = undefined;
            return resetUser.save();
        })
        .then(result => {
            res.redirect('/login');
        })
        .catch(err => {
            const error = new Error(err);
            error.httpStatusCode = 500;
            return next(error);
        });
}