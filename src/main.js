var jwt = require("jsonwebtoken");
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express()
const HEADER_NAME = process.env.HEADER_NAME || "jwt_token";

const debug = (event, ...rest) => {
  if(process.env.DEBUG)
    console.log({event, rest})
}

app.use(cookieParser())

app.get("/auth", function (req, res, next) {

  if(!req.cookies[HEADER_NAME]){
    debug('missing-cookie', {HEADER_NAME, headers: req.headers})
    res.sendStatus(401)
    return
  } 

  let val
  try {
    val = jwt.verify(req.cookies[HEADER_NAME], process.env.KEY, {algorithm: 'HS384'});
  }catch(ex){
    console.log({event:'jwt-val-exception', ex})
    debug('jwt-val-exception', req.cookies[HEADER_NAME])
    res.sendStatus(401);
    return
  }

  if(!val){
    debug('jwt-val-fail', val)
    res.sendStatus(401);
    return
  }

  if(val.expires < Date.now()){
    debug('jwt-val-expired', val)
    res.sendStatus(401);
    return
  }
  debug('headers', {headers: req.headers})
  try{
    if(val.roles.includes(req.headers.host)){
      debug('jwt-auth-host-success', { host: req.headers.host, roles: val.roles })
      res.sendStatus(200);
      return
    }else{
      console.log('jwt-auth-host-fail', { host: req.headers.host, roles: val.roles, id: val.id, username: val.username, discriminator: val.discriminator })
      res.sendStatus(401);
      return
    }
  }catch(error){
    debug('jwt-auth-host-error', { headers: req.headers, val })
    res.sendStatus(401);
    return
  }
});

process.on('unhandledRejection', error => {
  console.log({event:'unhandled-rejection', error});
});

const port = parseInt(process.env.PORT)
app.listen(port, () => console.log(`discord-sso-auth-validator listening on port ${port}${process.env.DEBUG ? " with debug output" : ""}!`));
