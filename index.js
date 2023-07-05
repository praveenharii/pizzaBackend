const express = require('express')
const bodyparser = require('body-parser')
const mysql = require('mysql')
const app = express()
const PORT = process.env.PORT;
const bcrypt = require("bcryptjs");
const stripe = require("stripe")(
  process.env.STRIPE_SECRET_TEST
);
const uuid = require('uuid').v4
const cors = require('cors')
var nodemailer = require("nodemailer");
const crypto = require("crypto");
const { log } = require('console')
const JWT_SECRET = process.env.JWT_SECRET;
const VerifyToken = require("./middlewares/verifyToken");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const encryptionKey = process.env.APP_ENCRYPTIONKEY;
const speakeasy = require("speakeasy");
const otpGenerator = require("otp-generator");
const optSecretKey = process.env.APP_OTP_SECRET_KEY;
require("dotenv").config();

app.use(cors());
app.use(express.json());
app.use(bodyparser.urlencoded({extended:false}))
app.use(bodyparser.json())



const db = mysql.createConnection({
  user: process.env.SQL_USER,
  host: process.env.SQL_HOST,
  password: process.env.SQL_PASSWORD,
  database: process.env.SQL_DATABASE,
});

//connect to mysql
db.connect(err => {
    if(err){
        throw err
    }
    console.log("Mysql Connected")
})

function verifyMfaToken(token, secret) {
  const isMfaValid = speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token: token,
    window: 0, // Set the window to 0 to only validate the current token
  });

  return isMfaValid;
}

app.post("/checkout", VerifyToken, async (req, res) => {
  let error, status;

  try {
    const { product, token, totalPrice } = req.body;
    const cardName = token.card.name;
    const cardLast4 = token.card.last4;
    const encryptedcardLast4 = CryptoJS.AES.encrypt(
      cardLast4,
      encryptionKey
    ).toString();

    db.query(
      "INSERT INTO usercarddetails (cardName, cardLast4digit) VALUES (?, ?)",
      [cardName, encryptedcardLast4],
      (err, results) => {
        if (err) {
          console.log(err);
          res.send("Error inserting data");
        } else {
          console.log("Data inserted successfully");

          stripe.customers
            .create({
              email: token.email,
              source: token.id,
            })
            .then((customer) => {
              return stripe.charges.create({
                amount: totalPrice * 100,
                currency: "myr",
                customer: customer.id,
                receipt_email: token.email,
                description: `Purchased the ${product.name}`,
                shipping: {
                  name: token.card.name,
                  address: {
                    line1: token.card.address_line1,
                    line2: token.card.address_line2,
                    city: token.card.address_city,
                    country: token.card.address_country,
                    postal_code: token.card.address_zip,
                  },
                },
              });
            })
            .then((charge) => {
              console.log("Charge:", charge);
              status = "success";
              res.json({ error, status });
            })
            .catch((error) => {
              console.log("Error:", error);
              status = "failure";
              res.json({ error, status });
            });
        }
      }
    );
  } catch (error) {
    console.log("Error:", error);
    status = "failure";
    res.json({ error, status });
  }
});

//const decryptedData = CryptoJS.AES.decrypt(encryptedData, encryptionKey).toString(CryptoJS.enc.Utf8);




app.post("/signup", async (req, res) => {
  const { email, password, mfaEnabled } = req.body;
  try {
    // Hash the password
    const encryptedPassword = await bcrypt.hash(password, 10);

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) {
        console.log(err);
        res.send("Error creating account");
      } else if (results.length > 0) {
        console.log("User already exists");
        res.send("User already exists");
      } else {
        const secret = speakeasy.generateSecret({ length: 20 });

        db.query(
          "INSERT INTO users (email, password, isMFAEnabled, mfaSecret) VALUES (?,?,?,?)",
          [email, encryptedPassword, mfaEnabled, secret.base32],
          (err, results) => {
            if (err) {
              console.log(err);
              res.send("Error creating account");
            } else {
              console.log("Account created successfully");

              // If MFA is enabled, send the user's secret key to the client for setup
              if (mfaEnabled) {
                res.json({ success: true, secret: secret.base32 });
              } else {
                res.send("Success");
              }
            }
          }
        );
      }
    });
  } catch (error) {
    console.log(error);
    res.send("Error creating account");
  }
});

app.post("/login", async (req, res) => {
  const { email, password, hash, otp } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Error fetching user" });
      }

      if (results.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const user = results[0];
      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return res.status(401).json({ message: "Incorrect password" });
      }

      let [hashValue, expires] = hash.split(".");
      let now = Date.now();
      if (now > parseInt(expires)) {
        return res.json({ message: "OTP Expired" });
      }

      let data = `${email}.${otp}.${expires}`;
      let newCalculateHash = crypto
        .createHmac("sha256", optSecretKey)
        .update(data)
        .digest("hex");

      if (newCalculateHash === hashValue) {
        const token = jwt.sign(
          {
            userId: user.id,
            email: user.email,
          },
          JWT_SECRET,
          { expiresIn: "1h" }
        );
        return res.json({ token, message: "Login successful" });
      }

      return res.status(401).json({ message: "Invalid OTP" });
    }
  );
});


app.post("/get-otp", async function (req, res) {
  const { email } = req.body;
  

  const otp = otpGenerator.generate(4, {
    digits: true,
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  console.log(otp);
  const ttl = 5 * 60 * 1000;
  const expires = Date.now() + ttl;
  const data = `${email}.${otp}.${expires}`;
  
  const hash = crypto
  .createHmac("sha256", optSecretKey)
  .update(data)
  .digest("hex");
  
  const fullHash = `${hash}.${expires}`;
  await sendEmail({
    from: "narendran@graduate.utm.my",
    to: email,
    subject: "Sign IN OTP",
    html: `<h1>Sign IN OTP is : ${otp}</h1>`,
  });

  return res.json({
    message: "Success",
    data: fullHash,
  });
});

app.post("/verify-otp", async function (req, res) {
  const { otp, hash, email } = req.body;
  console.log(req.body);
  let [hashValue, expires] = hash.split(".");
  let now = Date.now();
  if (now > parseInt(expires)) {
    return res.json({ message: "OTP Expired" });
  }

  let data = `${email}.${otp}.${expires}`;
  let newCalculateHash = crypto
    .createHmac("sha256", optSecretKey)
    .update(data)
    .digest("hex");

  if (newCalculateHash === hashValue) {
    return res.json({ message: "Success" });
  }
  return res.json({ message: "Invalid OTP" });
});



// Send email function
async function sendEmail(message) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: "linux2156@gmail.com",
      pass: process.env.PASSWORD,
    },
  });

  try {
    await transporter.sendMail(message);
    console.log("Email sent successfully!");
  } catch (error) {
    console.error("Error sending email: ", error);
  }
}

app.post("/forgotPassword", async (req, res) => {
  const { email } =req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.log(err);
        res.send("Error fetching user");
      } else if (results.length === 0) {
        res.send("User not found");
      } else {
        const tempPassword = crypto.randomBytes(4).toString("hex");
        const encryptedPassword = await bcrypt.hash(tempPassword, 10);
        db.query("UPDATE users SET password = ? WHERE email = ?", [
        encryptedPassword,
        email,
      ]);
      const msg = {
        to: email,
        from: "praveenhari1900@gmail.com",
        subject: "Forgot Password Link To new Password",
        text: `Your temporary password is: ${tempPassword}.`,
      };

      try {
        sendEmail(msg);
        console.log(`Email sent to ${email}`);
         res.send("New Temporary password sent");
      } catch (error) {
        `Error sending email to ${email}: ${error.message}`;
        throw err;
      }
    
      }
    }
  );
  
});







app.listen(PORT, ()=> {
    console.log('Server Is connected');
})