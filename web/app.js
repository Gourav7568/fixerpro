// require("dotenv").config();
const http = require('http');
const express = require('express');
const app = express();
const path = require('path');
const hbs = require('hbs');
const bcrypt = require('bcryptjs');
const port = 8080;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');


const User = require('../models/db');
const { now } = require('mongoose');

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.set('views', path.join(__dirname, '../templets/views'));


app.set('view engine', 'hbs');
app.set('templets', path.join(__dirname, '../templets'));

const pathreg = path.join(__dirname, '../templets/partials');
const staticpath = path.join(__dirname, '../public');

app.use('/photos', express.static('photos'));
app.use(express.static(staticpath));

hbs.registerPartials(pathreg)

app.get("/", (req, res) => {
    res.render("login");
});

app.get('/signup', (req, res) => {
    res.render("signup");
})

function verifyToken(req, res, next) {
    const token = req.cookies.jwt;

    if (!token) {
        // If no token is present, the user is not authenticated
        return res.send('Access Denied');
    }

    try {
        // Verify and decode the token
        const decoded = jwt.verify(token, "youaretheclientsformyapplicationsfor");

        // Attach the decoded user data to the request object for future use
        req.user = decoded;

        // Continue to the next middleware or route handler
        next();
    } catch (error) {
        // If token verification fails, the user is not authenticated
        res.redirect('/');
    }
}

app.get("/index", verifyToken, (req, res) => {
    res.render("index");
});
app.get("/about", verifyToken, (req, res) => {
    res.render("about");
});

app.get("/contact", verifyToken, (req, res) => {
    res.render("contact");
});



app.get('/logout', async (req, res) => {

    try {
        res.clearCookie("jwt");
        res.redirect('/');
    } catch (err) {
        res.status(500).send(err);
    }

})

app.post('/empdata', async (req, res) => {

    try {
        let pass = req.body.password;
        let confpassword = req.body.cpassword;
        let email = req.body.email;

        let creat = await User.findOne({ email: email })

        if (creat) {
            res.send("Email is already exist")
        }
        else if (pass == confpassword) {

            //Encrypt user password
            const encryptedPassword = await bcrypt.hash(pass, 10);
            //Create a newuser object
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                password: encryptedPassword,
                cpassword: encryptedPassword,
                number: req.body.number,
            });

            const token = await newUser.genrateToken();

            res.cookie("jwt", token, {
                expires: new Date(Date.now() + 1000000),
                httpOnly: true,
            })

            await newUser.save()
                .then(() => res.redirect("index"));
        }

        else {
            res.send("Invalid password");

        }

    }

    catch {
        ((err) => console.log(err));

    }
});

app.post('/login', async (req, res) => {
    const client = req.body.name;
    const password = req.body.password;

    // Find a user by the provided username
    const user = await User.findOne({ name: client });

    if (user) {
        // Check if the provided password matches the user's hashed password
        const passwordMatch = await bcrypt.compare(password, user.password);
        const token = await user.genrateToken();

        res.cookie("jwt", token, {
            expires: new Date(Date.now() + 50000),
            httpOnly: true,
        })

        if (passwordMatch) {
            // Redirect to the index page upon successful login
            res.redirect("/index");
        } else {
            // Password doesn't match
            res.send('Login Failed: Incorrect Password');
        }
    } else {
        // User with the provided username doesn't exist
        res.send('Login Failed: User Not Found');
    }
});

app.get('*', (req, res) => {
    res.status(404).render(
        'oops')
})

app.listen(port, () => {
    console.log(`server is listening on port ${port}`);
});

