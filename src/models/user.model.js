import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import validator from "validator";

const userSchema = new Schema(
    {
       
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: [true, "email already exist"],
            lowecase: true,
            trim: true,
            validate: [validator.isEmail, "Invalid Email Address"],
        },
        username: {
            type: String,
            required: [true, "username is required"],
            trim: true,
            index: true,
            unique:true,
        },      
        password: {
            type: String,
            required: [true, "Password is required"],
        },
        profileUrl: {
            type: String,
        },
          gender:{
            type:String,
            enum:['male','female','other']
          },   
          country:{
            type:String,
            enum:['india' , 'other']
          },  
        refreshToken: {
            type: String,
        },
    },
    {
        timestamps: true,
    }
);

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10);
    next();
});

userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password);
};

userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            username: this.username,
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        }
    );
};

userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
        }
    );
};

export const User = mongoose.model("User", userSchema);
