const mongoose = require('mongoose');

const connectDb = async (connectionString) => {
  return mongoose.connect(connectionString);
};

module.exports = connectDb;
