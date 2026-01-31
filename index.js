require('dotenv').config();
const express = require('express');
const app = express();
const bcrypt = require("bcrypt");
const session = require("express-session");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const connectdb = require("./config/db.js");
const User = require("./models/User.js");
const sendVerificationEmail = require("./utils/email.js");
const { signupSchema, loginSchema } = require("./utils/validate.js");
const helmet = require("helmet");
connectdb();

const PORT = process.env.PORT;

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(session({
  secret: "mysupersecret##",
  resave: false,
  saveUninitialized: false,
}));

function isAuth(req, res, next) {
  if (req.session.userId) next();
  else res.redirect("/login");
}

const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 5, // 5 attempts allowed
  message: "Too many login attempts. Try again later.",
});


app.get('/signup', (req, res) => res.render("signup.ejs"));

app.post("/signup", async (req, res) => {
  try {
    const { error } = signupSchema.validate(req.body);
    if (error) return res.send(error.details[0].message);

    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.send("User already exists");

    const hashedPassword = await bcrypt.hash(password, 10);
    const token = crypto.randomBytes(32).toString("hex");

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      verificationToken: token,
      isVerified: false,
    });

    await newUser.save();
    await sendVerificationEmail(email, token);

    res.send("Signup successful! Check email to verify.");
  } catch (err) {
    console.error(err);
    res.send("Signup error");
  }
});

app.get('/login', (req, res) => res.render("login.ejs"));

app.get("/verify-email/:token", async (req, res) => {
  try {
    const user = await User.findOne({ verificationToken: req.params.token });
    if (!user) return res.send("Invalid or expired token");

    user.isVerified = true;
    user.verificationToken = null;
    await user.save();

    res.send("Email verified successfully! You can now login.");
  } catch (err) {
    console.error(err);
    res.send("Verification failed");
  }
});

app.post("/login",loginLimiter, async (req, res) => {
  try {
    const { error } = loginSchema.validate(req.body);
    if (error) return res.send(error.details[0].message);

    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (!existingUser) return res.send("User not found");
    if (!existingUser.isVerified) return res.send("Please verify your email first");

    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) return res.send("Wrong password");

    req.session.userId = existingUser._id;
    res.redirect("/home");

  } catch (error) {
    console.error(error);
    res.send("Login error");
  }
});

app.get('/home', isAuth, (req, res) => res.render("home.ejs"));

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});


app.get("/forgot-password", (req, res) => {
  res.render("forgot-password");
});

app.get("/reset-password", (req, res) => {
  res.render("reset-password");
});


app.post("/forgot-password",async (req,res)=>{
const {email} = req.body;

const user = await User.findOne({email});
if (!user) return res.send("If email exists, OTP sent");
 const otp = Math.floor(100000 + Math.random() * 900000).toString();

  user.resetOTP = otp;
  user.otpExpiry = Date.now() + 10 * 60 * 1000; // 10 min

  await user.save();
   const transporter = nodemailer.createTransport({
     service: "gmail",
     auth: {
       user: process.env.EMAIL_USER,
       pass: process.env.EMAIL_PASS,
     },
   }); 
  
   await transporter.sendMail({
    to: email,
    subject: "Password Reset OTP",
    html: `<h2>Your OTP is: ${otp}</h2><p>Valid for 10 minutes</p>`
  });

  res.redirect("/reset-password");

})

app.post("/reset-password",async(req,res)=>{
   const { email, otp, newPassword } = req.body;

  const user = await User.findOne({
    email,
    resetOTP: otp,
    otpExpiry: { $gt: Date.now() },
  });

  if (!user) return res.send("Invalid or expired OTP");

  user.password = await bcrypt.hash(newPassword, 10);
  user.resetOTP = null;
  user.otpExpiry = null;

  await user.save();

  res.send("Password reset successful");
})


app.listen(PORT, () => console.log(`Server is running on ${PORT}`));
