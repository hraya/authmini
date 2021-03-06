require('dotenv').config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require('jsonwebtoken');

const db = require("./database/dbConfig.js");

const server = express();




server.use(express.json());
server.use(cors());


server.post("/api/register", (req, res) => {
  const credentials = req.body;
  //hash the password
  const hash = bcrypt.hashSync(credentials.password, 10);
  credentials.password = hash;
  //then save the user
  db("users")
    .insert(credentials)
    .then(ids => {
      const id = ids[0];
      res.status(201).json({ newUserId: id });
    })
    .catch(err => {
      res.status(500).json({ err });
    });
  });

  const jwtSecret = process.env.JWT_SECRET || 'add a secret to your .env file with this key';
  function generateToken(user){
    const jwtPayload = {
        ...user,
        hello:'WEBPT2',
        roles:['admin', 'root']
    };
    const jwtOptions = {
        expiresIn:'1h',
    }
    return jwt.sign(jwtPayload, jwtSecret, jwtOptions)
}

  server.post("/api/login", (req, res) => {
    const creds = req.body;
    db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      console.log(user)
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        //found the user
        const token = generateToken(user)
        res.status(200).json({ welcome: user.username, token });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err => {
      res.status(500).json({ err });
    });
});
// protect this route, only authenticated users should see it
server.get("/api/users", protected, checkRole('admin'), (req, res) => {
    // console.log('/n** decoded token information***/n', req.decodedToken);
  db("users")
    .select("id", "username", "password") //password is there for example purposes
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
  });
  
  function protected(req, res, next) {
    const token = req.headers.authorization;
    if(token){
        jwt.verify(token, jwtSecret, (err, decodedToken)=>{
            if(err){
                //token verification failed
                res.status(401).json({message:'invalid token'})
            }else{
                //token is valid
                req.decodedToken = decodedToken;
                next();
            }
        })
    }else{
        res.status(401).json({message:'no token provided'})/// normally say you are not authorized
    }
  }

  function checkRole(role){
      return function(req,res,next){
          if(req.decodedToken && req.decodedToken.roles.includes(role)){
              next();
          }else{
              res.status(403).json({message:'you shall not pass! forbidden'})
          }
      }
  }

  const port = process.env.PORT || 3300;
  server.listen(port, () => console.log("\nrunning on port 3300\n"));
  