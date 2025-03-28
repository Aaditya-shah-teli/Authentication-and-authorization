const cookieParser = require('cookie-parser');
const express = require('express');
const userModel = require('./models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

// Hard-coded JWT secret key
const JWT_SECRET = "your_jwt_secret_key"; // Replace this with your secret key

app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.cookie("name", "Aaditya sah");
    res.render('index');
});

app.post('/create', async (req, res) => {
    const { name, email, password, age } = req.body;

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        let createdUser = await userModel.create({
            name,
            email,
            password: hashedPassword,
            age
        });

        let token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, { httpOnly: true, secure: true });

        res.send(createdUser);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error creating user');
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});
app.post('/login', async (req, res) => {
    console.log("Received email:", req.body.email);  // Log to check the email
    let user = await userModel.findOne({ email: new RegExp('^' + req.body.email + '$', 'i') });
    
    if (!user) return res.status(404).send("User not found");

    try {
        const result = await bcrypt.compare(req.body.password, user.password);
        if (result) {
            let token = jwt.sign({ email: user.email }, JWT_SECRET);
            res.cookie("token", token);
            res.send("You can login");
        } else {
            res.status(401).send("Invalid password");
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Error logging in");
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie("token");
    res.redirect('/');
});

app.listen(3000, () => console.log('Running on port 3000'));