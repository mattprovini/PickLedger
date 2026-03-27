var express=require('express');
var router=express.Router();

/* Home Page */
router.get('/', function(req, res) {
        res.render('home');
});

/* Login Page */
router.get('/login', function(req, res) {
        res.render('login');
});

/* Register Page */
router.get('/register', function(req, res) {
        res.render('register');
});

module.exports=router;


