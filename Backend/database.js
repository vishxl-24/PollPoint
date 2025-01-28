// connect command mpngoose.connect method
require("dotenv").config();
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);

    console.log(" mongo db   connection successfull");
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
};

connectDB();
