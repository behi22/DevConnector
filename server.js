import express from 'express';
import connectDB from './config/db.js';
import path from 'path';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

dotenv.config(); // Load environment variables

// Resolving dirname for ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Connect Database
connectDB();

// Init Middleware
app.use(express.json());

// Define Routes using import
import usersRouter from './routes/api/users.js';
import authRouter from './routes/api/auth.js';
import profileRouter from './routes/api/profile.js';
import postsRouter from './routes/api/posts.js';

// Define the API routes
app.use('/api/users', usersRouter);
app.use('/api/auth', authRouter);
app.use('/api/profile', profileRouter);
app.use('/api/posts', postsRouter);

// Use the client app
app.use(express.static(path.join(__dirname, '/client/build')));

// Render client for any path
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '/client/build/index.html'));
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port: ${PORT}`));
