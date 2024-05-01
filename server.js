const express = require('express')
const cors = require('cors')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const mongoose  = require('mongoose')
const cookieParser = require("cookie-parser");
const User = require('./models/User.js')
require('dotenv').config()

// express
const app = express()
app.use(cors())
app.use(express.json())
app.use(cookieParser()) 


// mongoose
mongoose.connect(process.env.MONGO_URI)


// register user
const salt = bcrypt.genSaltSync(10); //hashing and salting
app.post('/register',async(req,res)=>{
   const {username,password} = req.body
 try{
    regData = await User.create({
        username,
        password:bcrypt.hashSync(password,salt)})
    res.json(regData)
 }catch(error){
    res.status(400).json(error)
 }

})



app.post('/login', async (req, res) => {
   const { username, password } = req.body;
   try {
      const loginData = await User.findOne({ username });

      // Check if user exists
      if (!loginData) {
         return res.status(400).json({ error: 'User not found' });
      }

      const loginOk = bcrypt.compareSync(password, loginData.password);

      // Check if password is correct
      if (loginOk) {
         jwt.sign({ username, id: loginData._id }, process.env.SECRET_KEY, {}, (error, token) => {
            if (error) {
               throw error;
            } else {
               // Set token as a cookie
               res.cookie('token', token, {
                  httpOnly: true,
                  secure: process.env.NODE_ENV === 'production', // Set secure flag in production
                  sameSite: 'strict', // Enforce SameSite attribute
                  path: '/', // Set cookie path
               }).json({
                  id: loginData._id,
                  username
               });
            }
         });
      } else {
         res.status(400).json({ error: 'Wrong credentials' });
      }
   } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
   }
});

// check profile log in
app.get('/profile', (req, res) => {
   const { token } = req.cookies;
   jwt.verify(token, process.env.SECRET_KEY, {}, (err, info) => {
      if (err) {
         // If there's an error with token verification, respond with an error status
         res.status(401).json({ error: 'Unauthorized' });
      } else {
         // If token verification is successful, respond with the decoded information
         res.json(info);
      }
   });
});




const Port = 4000

app.listen(Port,()=>{
    console.log(`app listening on ${Port} `)
})