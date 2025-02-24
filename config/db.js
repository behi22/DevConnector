import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config(); // Load environment variables

const db = process.env.MONGO_URI;

const connectDB = async () => {
  try {
    await mongoose.connect(db);

    console.log('MongoDB Connected...');
  } catch (err) {
    console.error(err.message);
    // Exit process with Failure
    process.exit(1);
  }
};

export default connectDB;
