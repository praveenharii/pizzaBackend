const express = require('express')
const bodyparser = require('body-parser')
const mysql = require('mysql')
const app = express()
const PORT = 3001
const bcrypt = require("bcryptjs");
const stripe = require("stripe")(
  "sk_test_51NHtYKET8OWZGN7d03SmOncOkXk5g060Y2N3PlEA4jrQ2KnGvVj8XHwzMyiTr3UKyFiWn41gTohalWAeAzjNfngZ00YPhFuaHE"
);
const uuid = require('uuid').v4
const cors = require('cors')
var nodemailer = require("nodemailer");
const crypto = require("crypto");
const { log } = require('console')
const JWT_SECRET = "asdwdawdawrweraerdfedrtewter543w532wrwe32455213rw2";
const VerifyToken = require("./middlewares/verifyToken");
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const encryptionKey = "erewfewfewfweferer234324143wdqere3";
require("dotenv").config();

app.use(cors());
app.use(express.json());
app.use(bodyparser.urlencoded({extended:false}))
app.use(bodyparser.json())



const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "",
  database: "nodemysql",
});

//connect to mysql
db.connect(err => {
    if(err){
        throw err
    }
    console.log("Mysql Connected")
})


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
  const { email, password } = req.body;
   const encryptedPassword = await bcrypt.hash(password, 10);
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    
    if (err) {
      console.log(err);
      res.send("Error creating account");
    } else if (results.length > 0) {
      console.log("User already exists");
      res.send("User already exists");
    } else {
      // Insert new user
      db.query(
        "INSERT INTO users (email, password) VALUES (?,?)",
        [email, encryptedPassword],
        (err, results) => {
          if (err) {
            console.log(err);
            res.send("Error creating account");
          } else {
            console.log("Account created successfully");
            res.send("Success");
          }
        }
      );
    }
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        console.log(err);
        res.send({message:"Error fetching user"});
      } else if (results.length === 0) {
        // User not found
        res.send({message:"User not found"});
      } else {
        // User found, check password
        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (match) {
           const token = jwt.sign(
             {
               userId: user.id,
               email: user.email,
             },
             JWT_SECRET,
             { expiresIn: "1h" } 
           );

           // Send the token to the frontend
           res.json({ token, message: "Login successful" });
        } else {
          res.send({message: "Incorrect password"});
        }
      }
    }
  );
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