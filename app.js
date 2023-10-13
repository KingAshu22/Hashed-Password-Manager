const express = require("express");
const session = require("express-session");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();

// MongoDB connection
mongoose.connect("mongodb://localhost/password-manager", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware setup
app.use(express.json());
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({ secret: "your-secret-key", resave: true, saveUninitialized: true })
);

// Define User Schema and Model (using mongoose)
const UserSchema = new mongoose.Schema({
  username: String,
  displayName: String,
  password: String,
  vault: [
    {
      websiteName: String,
      username: String,
      password: String,
      lastUpdated: Date,
    },
  ],
});

const User = mongoose.model("User", UserSchema);

// Define routes and middleware
app.set("view engine", "ejs");

// Function to generate a random salt
function generateSalt() {
  return bcrypt.genSaltSync(10);
}

// Function to hash a password with a salt
function hashPassword(password, salt) {
  return bcrypt.hashSync(password, salt);
}

// Function to encrypt a password
function encrypt(text, id) {
  const algorithm = "aes-256-cbc";
  const key = crypto.scryptSync(id, "3!pB#9cS$eRtYvXm&lN1oA5lZ", 32);
  const iv = Buffer.alloc(16, 0); // Initialization vector

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedPassword = cipher.update(text, "utf8", "hex");
  encryptedPassword += cipher.final("hex");

  return encryptedPassword;
}

// Function to decrypt a password
function decrypt(encryptedText, id) {
  const algorithm = "aes-256-cbc";
  const key = crypto.scryptSync(id, "3!pB#9cS$eRtYvXm&lN1oA5lZ", 32);
  const iv = Buffer.alloc(16, 0); // Initialization vector

  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decryptedPassword = decipher.update(encryptedText, "hex", "utf8");
  decryptedPassword += decipher.final("utf8");

  return decryptedPassword;
}

app.get("/", (req, res) => {
  res.render("home");
});

// Register Page
app.get("/log-in", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const user = await User.findOne({ username: username });

    if (!user) {
      return res.status(401).send("Invalid username or password");
    }

    if (bcrypt.compareSync(password, user.password)) {
      req.session.user = { _id: user._id };
      res.redirect("dashboard");
    } else {
      res.status(401).send("Invalid username or password");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred while logging in");
  }
});

app.get("/dashboard", async (req, res) => {
  const user = await User.findOne({ _id: req.session.user._id });

  res.render("dashboard", {
    user: user,
  });
});

app.get("/vault", async (req, res) => {
  const user = await User.findOne({ _id: req.session.user._id });

  // Decrypt the passwords in the vault
  user.vault.forEach((entry) => {
    entry.username = decrypt(entry.username, user.id);
    entry.password = decrypt(entry.password, user.id);
  });

  res.render("vault", {
    user: user,
  });
});

app.post("/register", async (req, res) => {
  const displayName = req.body.name;
  const username = req.body.username;
  const password = req.body.password;

  try {
    const existingUser = await User.findOne({ username: username });

    if (existingUser) {
      return res.status(400).send("Username already exists");
    }

    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);

    const user = new User({
      username: username,
      password: hashedPassword,
      displayName: displayName,
    });

    await user.save();

    req.session.user = { _id: user._id };
    res.redirect("dashboard");
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred while registering");
  }
});

app.get("/create-vault", (req, res) => {
  res.render("create-vault");
});

app.post("/create-vault", async (req, res) => {
  const websiteName = req.body.websiteName;
  const username = req.body.username;
  const password = req.body.password;

  try {
    // Find the user by their ID
    const user = await User.findOne({ _id: req.session.user._id });

    // Encrypt the password
    const encryptedUsername = encrypt(username, user.id);
    const encryptedPassword = encrypt(password, user.id);

    // Push the encrypted password to the vault
    user.vault.push({
      websiteName: websiteName,
      username: encryptedUsername,
      password: encryptedPassword,
      lastUpdated: Date.now(),
    });

    // Save the user with the updated vault
    await user.save();

    res.redirect("/vault"); // Redirect to the vault page after adding the password
  } catch (err) {
    console.error(err);
    res.status(500).send("An error occurred while creating a vault");
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
