import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2"
import env from "dotenv";

env.config();
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = process.env.SALT_ROUNDS;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//creating session and using through passport package
app.use(session({
  secret: process.env.SECRETKEY,
  resave: false,
  saveUninitialized: true,
  cookie:{
    maxAge: 1000*60*60*24, // 1 day
  }
}))
app.use(passport.initialize())
app.use(passport.session())


const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  password:process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE,
  port: process.env.PG_PORT
})
db.connect();

function checkEmail(email){}

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/auth/google",passport.authenticate("google",{
  scope:["profile","email"]
}))
app.get("/auth/google/secrets",passport.authenticate("google",{
  successRedirect:"/todos",
  failureRedirect:"/login"
}))
let items = [];

app.get("/todos", async (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * from items WHERE user_id=$1",[req.user.id]);
    items = result.rows
    res.render("todos.ejs", {
      listTitle: "Today",
      listItems: items,
    });
  }else {
    res.redirect("/login");
  }
});

app.post("/add", async (req, res) => {
  const item = req.body.newItem;
  try {
    await db.query("INSERT INTO items (title,user_id) VALUES ($1,$2)",[item,req.user.id]);
    res.redirect("/todos");
  } catch (error) {
    console.log(error);
    res.redirect("/todos")
  }
});

app.post("/edit", async (req, res) => {
    const id = parseInt(req.body["updatedItemId"])
    const title = req.body["updatedItemTitle"]
    try {
      await db.query("UPDATE items SET title = $1 WHERE id = $2 AND user_id=$3",[title,id,req.user.id]);
      res.redirect("/todos");
    } catch (error) {
      console.log(error);
      res.redirect("/todos")
    }
});

app.post("/delete", async (req, res) => {
  const id = parseInt(req.body["deleteItemId"])
  try {
    await db.query("DELETE FROM items WHERE id=$1 AND user_id=$2",[id,req.user.id]);
    res.redirect("/todos")
  } catch (error) {
    console.log(error);
    res.redirect("/todos")
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body["username"];
  const password = req.body["password"];
  try {
    const result = await db.query("SELECT * FROM register WHERE username = $1",[email]);
    if(result.rows.length>0){
      res.send("User already exists...Try logging in")
    }
    else{
      bcrypt.hash(password,saltRounds,async (err,hash)=>{
        if(err){
          console.log("error hashing password",err);
        }
        else{
          const result = await db.query("INSERT INTO register (username,password) VALUES ($1,$2) RETURNING *",[email,hash]);
          const user = result.rows[0]
          req.login(user,(err)=>{
            if(err) console.log(err)
            else res.redirect("/todos");
          })
        }
      });  
    }
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
}); 

app.post("/login", passport.authenticate("local" , {
  successRedirect: "/todos",
  failureRedirect: "/login"
}));

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    else res.redirect("/");
  });
});

//cookies using passport package
passport.use("local",new Strategy(async function verify(username,password,cb){
  try {
    const result = await db.query("SELECT * FROM register WHERE username = $1",[username]);
    if(result.rows.length!==0){
      const user = result.rows[0]
      const hashedPass = user.password;
      bcrypt.compare(password,hashedPass,(err,result)=>{
        if(err){
          return cb(err)
        }
        else{
          if(result){
            return cb(null,user)
          }
          else{
            return cb(null,false) //helping isAuthenticated to verify true/false
          }
        }
      })
    }
    else{
      return cb("User not found")
    }
  } 
  catch (error) {
    return cb(error)
  }
}))

//google authentication
passport.use("google",new GoogleStrategy({
  clientID : process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},async (accessToken,refreshToken,profile,cb)=>{
  //console.log(profile)
  try {
    const result= await db.query("SELECT * FROM register WHERE username=$1",[profile.email])
    if(result.rows.length===0){
      const newUser = await db.query("INSERT INTO register (username,password) VALUES ($1,$2) RETURNING *",[profile.email,"google"])
      cb(null,newUser.rows[0])
    }
    else{
      cb(null,result.rows[0])
    }
  } catch (error) {
    cb(error)
  }
}))

passport.serializeUser((user,cb)=>{
  cb(null,user);
})
passport.deserializeUser((user,cb)=>{
  cb(null,user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
