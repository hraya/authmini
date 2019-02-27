const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const db = require("./database/dbConfig.js");

const server = express();

const sessionConfig = {
  secret: "nobody.knows.this",
  name: "monkey", // default to connect.sid
  httpOnly: true, //JS can't access this
  resave: false,
  saveUninitialize: false, //laws!
  cookie: {
    secure: false, //over httpS production set to true
    maxAge: 1000 * 60 * 1
  },
  store: new KnexSessionStore({
    tablename: "sessions",
    sidfieldname: "sid",
    knex: db,
    createtable: true,
    clearInterval: 1000 * 60 * 60 //removes only expired sessions
  })
};
server.use(session(sessionConfig));

server.use(express.json());
server.use(cors());

server.get("/", (req, res) => {
  res.send("Its Alive!");
});

server.post("/registers", (req, res) => {
  const credentials = req.body;
  //hash the password
  const hash = bcrypt.hashSync(credentials.password, 10);
  credentials.password = hash;
  //then save the user
  db("users")
    .insert(credentials)
    .then(ids => {
      const id = ids[0];
      req.session.userId = id;
      res.status(201).json({ newUserId: id });
    })
    .catch(err => {
      res.status(500).json({ err });
    });
  });

  server.post("/login", (req, res) => {
    const creds = req.body;
    db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.userId = user.id;
        //found the user
        res.status(200).json({ welcome: user.username });
      } else {
        res.status(401).json({ message: "You shall not pass!" });
      }
    })
    .catch(err => {
      res.status(500).json({ err });
    });
});
// protect this route, only authenticated users should see it
server.get("/api/users", protected, (req, res) => {
  db("users")
    .select("id", "username", "password") //password is there for example purposes
    .then(users => {
      console.log(req.session)
      res.json(users);
    })
    .catch(err => res.send(err));
  });
  
  server.get("/logout", (req, res) => {
    if (req.session) {
      req.session.destroy(err => {
        if (err) {
          res.send("You cannot leave!");
        } else {
          res.send("Peace homie!");
        }
      });
    }
  });
  
  function protected(req, res, next) {
    if (req.session && req.session.userId) {
      next();
    } else {
      res.status(401).json({ message: "Not Authorized!!!!" });
    }
  }
  server.listen(3300, () => console.log("\nrunning on port 3300\n"));
  