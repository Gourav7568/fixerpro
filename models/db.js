const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const { Schema } = mongoose;
const jwt = require("jsonwebtoken")


mongoose.connect('mongodb://localhost:27017/gourav', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('databse connected..'))
  .catch((error) => console.log(error));

const userSchema = new Schema({
  name: {
    type: String,
    require: true
  },
  email: {
    type: String,
    require: true
  },
  password: String,
  cpassword:String,
  number: Number,
  tokens:[{
    token:{
      type: String,
      require: true
    }
  }]
})

//generating token
userSchema.methods.genrateToken = async function(){
  try{

    const token = jwt.sign({_id:this._id.toString()},"youaretheclientsformyapplicationsfor");
    this.tokens = this.tokens.concat({token:token});
    await this.save();
    return token;

  }
  catch(err){
      console.log(err);
  }
}

const User = mongoose.model('User', userSchema);
module.exports = User;


