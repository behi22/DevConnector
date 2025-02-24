import mongoose from 'mongoose';

// Middleware to check for a valid ObjectId
const checkObjectId = (idToCheck) => (req, res, next) => {
  if (!mongoose.Types.ObjectId.isValid(req.params[idToCheck])) {
    return res.status(400).json({ msg: 'Invalid ID' });
  }
  next();
};

export default checkObjectId;
