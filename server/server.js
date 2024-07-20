import express from 'express';
import * as dotenv from 'dotenv';
dotenv.config();
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';

//Schema
import User from './Schema/User.js';

const server = express();

server.use(express.json());
server.use(cors());

const port = process.env.PORT || 5100;

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );

  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

const generateUserName = async (email) => {
  let username = email.split('@')[0];

  let userNameExists = await User.exists({
    'personal_info.username': username,
  }).then((result) => result);

  userNameExists ? (username += nanoid().substring(0, 5)) : '';

  return username;
};

//Sign up
server.post('/signup', (req, res) => {
  let { fullname, email, password } = req.body;

  //validating the data from frontend
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: 'Full name must be at least 3 letters long' });
  }

  if (!email.length) {
    return res.status(403).json({ error: 'Enter Email' });
  }

  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: 'Email is invalid' });
  }

  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        'Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters',
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let username = await generateUserName(email);

    let user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDataToSend(u));
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(500).json({ error: 'Email already exists' });
        }

        return res.status(500).json({ error: err.message });
      });
  });
});

//Sign in
server.post('/signin', (req, res) => {
  let { email, password } = req.body;

  User.findOne({ 'personal_info.email': email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: 'Email not found' });
      }

      bcrypt.compare(password, user.personal_info.password, (err, result) => {
        if (err) {
          return res
            .status(403)
            .json({ error: 'Error occured while loging in, please try again' });
        }

        if (!result) {
          return res.status(403).json({ error: 'Incorrect password' });
        } else {
          return res.status(200).json(formatDataToSend(user));
        }
      });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ error: err.message });
    });
});

try {
  await mongoose.connect(process.env.MONGO_URL, { autoIndex: true });
  server.listen(port, () => {
    console.log(`server running on port ${port}....`);
  });
} catch (error) {
  console.log(error);
  process.exit(1);
}
