const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Please provide a username'],
      minlength: [3, 'username is too short'],
      maxlength: [12, 'username is too big'],
      match: [/^[\d]+$/, 'username must contain only letters and numbers'],
    },
    email: {
      type: String,
      required: [true, 'Please provide an email'],
      match: [
        /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
        'Please insert a valid e-mail',
      ],
      unique: true,
    },
    password: {
      type: String,
      required: [true, 'Please provide a password'],
      minlength: [4, 'Password should have at least 4 characters'],
    },
    avatar: {
      type: String,
      enum: ['cloudy', 'puppy', 'witch'],
      default: 'cloudy',
    },
  },
  { timestamps: true },
);

//hashes the password before it's actually saved in the db
UserSchema.pre('save', async function () {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);

  this.password = hashedPassword;
});

UserSchema.methods.comparePassword = async function (receivedPassword) {
  const isAMatch = await bcrypt.compare(receivedPassword, this.password);

  return isAMatch;
};

UserSchema.methods.createJWT = async function () {
  const payload = {
    userId: this._id,
    name: this.username,
  };
  const token = jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_LIFETIME,
  });

  return token;
};
