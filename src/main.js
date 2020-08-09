var jwt = require("jsonwebtoken");
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express()
const HEADER_NAME = "jwt_token";

const debug = (event, ...rest) => {
  if(process.env.DEBUG)
    console.log({event, rest})
}

app.use(cookieParser())

app.get("/auth", function (req, res, next) {

  if(!req.cookies[HEADER_NAME]){
    debug('missing-cookie', {HEADER_NAME})
    res.sendStatus(401)
    return
  } 

  let val
  try {
    val = jwt.verify(req.cookies[HEADER_NAME], process.env.KEY);
  }catch(ex){
    console.log({event:'jwt-val-exception', ex})
  }
    
  if(!val){
    debug('jwt-val-fail', {val})
    res.sendStatus(401);
    return
  }

  if(val.expires < Date.now()){
    debug('jwt-val-expired', {val})
    res.sendStatus(401);
    return
  }

  if(!val.admin){
    debug('jwt-val-forbidden', {val})
    res.sendStatus(401);
    return
  }

  debug('jwt-val-ok', {val})
  res.sendStatus(200);
  return
});

process.on('unhandledRejection', error => {
  console.log({event:'unhandled-rejection', error});
});

const port = parseInt(process.env.PORT)
app.listen(port, () => console.log(`discord-sso-auth-validator listening on port ${port}${process.env.DEBUG ? " with debug output" : ""}!`));
