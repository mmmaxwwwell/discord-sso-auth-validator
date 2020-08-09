var jwt = require("jsonwebtoken");
const express = require("express");
const expressWs = require("express-ws");
const cookieParser = require("cookie-parser");
const { app, getWss, applyTo } = expressWs(express());
const fs = require("fs");
const HEADER_NAME = "jwt_token";
const Discord = require("discord.js");
const { SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION } = require("constants");
const client = new Discord.Client();

app.use(cookieParser());

client.on("ready", () => {
  console.log(`Logged in as ${client.user.tag}!`);
});

client.login(process.env.DISCORD_TOKEN);

app.get("/auth", function (req, res, next) {
  if(!req.cookies[HEADER_NAME]){
    res.sendStatus(401)
    return
  } else {
    try {
      const val = jwt.verify(req.cookies[HEADER_NAME], process.env.KEY);

      if(!val){
        res.sendStatus(401);
        return
      }else{
        let user
        try{
          user = client.guilds.cache.first().members.cache.find(x => x.user.id == val.id)
        }catch{

        }

        if(!user){
          client.channels.cache.get(process.env.CHANNEL_ID).send(`@here ACCESS DENIED to ${val.username}#${val.discriminator} due to user not found`);
          res.sendStatus(401);
          return
        }

        if(!user._roles.includes(process.env.ADMIN_ROLE_ID)){
          client.channels.cache.get(process.env.CHANNEL_ID).send(`@here ACCESS DENIED to ${val.username}#${val.discriminator} due to not an admin`);
          res.sendStatus(401)
          return
        }else if(!val.mfa_enabled){
          client.channels.cache.get(process.env.CHANNEL_ID).send(`@HERE ACCESS DENIED to ${val.username}#${val.discriminator} due to no 2fa`);
          res.sendStatus(401)
          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
        }else{
          client.channels.cache.get(process.env.CHANNEL_ID).send(`AUTHORIZED ${val.username}#${val.discriminator} for ${req.header('X-Original-URI')}`);
          res.sendStatus(200)
          return
        }
      }
    } catch (err) {
      console.error(err);
      res.sendStatus(401);
      return
    }
  }
});

process.on('unhandledRejection', error => {
  console.log({event:'unhandled-rejection', error});
});

const port = parseInt(process.env.PORT)
app.listen(port, () => console.log(`Example app listening on port ${port}!`));
