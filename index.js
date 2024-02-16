const express = require('express');
const mongodb = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();

app.use(express.json());


const uri = 'mongodb://localhost:27017';
const dbName = 'mydb';

const client = new mongodb.MongoClient(uri, { useUnifiedTopology: true });


client.connect().then(() => {
  console.log('Connected to MongoDB');

  
  const users = client.db(dbName).collection('users');

  
  app.post('/register', async (req, res) => {
    try {
      
      const { username, password } = req.body;

      
      if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
      }

      
      const existingUser = await users.findOne({ username });
      if (existingUser) {
        return res.status(409).json({ message: 'Username already taken' });
      }

      
      const hashedPassword = await bcrypt.hash(password, 10);

    
      const result = await users.insertOne({ username, password: hashedPassword });

      const token = jwt.sign({ id: result.insertedId }, 'secret', { expiresIn: '1h' });

      
      res.status(201).json({ token });
    } catch (err) {
    
      console.error(err);
      res.status(500).json({ message: 'Something went wrong' });
    }
  });

  
  app.post('/login', async (req, res) => {
    try {
      
      const { username, password } = req.body;

      
      if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
      }

      
      const user = await users.findOne({ username });
      if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

    
      const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

   
      res.status(200).json({ token });
    } catch (err) {
   
      console.error(err);
      res.status(500).json({ message: 'Something went wrong' });
    }
  });


  const verifyToken = (req, res, next) => {
    try {
      
      const token = req.headers.authorization.split(' ')[1];

      
      const decoded = jwt.verify(token, 'secret');

      
      req.userId = decoded.id;

      
      next();
    } catch (err) {
      
      console.error(err);
      res.status(401).json({ message: 'Invalid token' });
    }
  };


  app.get('/profile', verifyToken, async (req, res) => {
    try {
      
      const userId = req.userId;

    
      const user = await users.findOne({ _id: mongodb.ObjectId(userId) });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }

   
      res.status(200).json({ username: user.username });
    } catch (err) {
      
      console.error(err);
      res.status(500).json({ message: 'Something went wrong' });
    }
  });


  app.listen(3000, () => {
    console.log('Server listening on port 3000');
  });
}).catch((err) => {
  
  console.error(err);
  process.exit(1);
});
