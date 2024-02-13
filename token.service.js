const jwt = require("jsonwebtoken")
const CryptoJS = require("crypto-js")
const moment = require('moment');
require('dotenv').config();


const CRYPTO_SECRET_KEY = process.env.CRYPTO_SECRET_KEY
const CRYPTO_SECRET_IV = process.env.CRYPTO_SECRET_IV
const JWT_SECRET = process.env.JWT_SECRET
const JWT_ACCESS_EXPIRATION_MINUTES = process.env.JWT_ACCESS_EXPIRATION_MINUTES
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET
const JWT_REFRESH_EXPIRATION_DAYS = process.env.JWT_REFRESH_EXPIRATION_DAYS

const key = CryptoJS.enc.Hex.parse(String(CRYPTO_SECRET_KEY));
const iv = CryptoJS.enc.Hex.parse(String(CRYPTO_SECRET_IV));

const encryptUserID = async (userId) => {
    const value = CryptoJS.AES.encrypt(String(userId), key, {
        iv: iv,
        padding: CryptoJS.pad.ZeroPadding,
    }).toString();
    return value;
};

const decryptUserID = async (value) => {
    const userId = CryptoJS.AES.decrypt(value, key, {
        iv: iv,
        padding: CryptoJS.pad.ZeroPadding,
    }).toString(CryptoJS.enc.Utf8);
    return userId;
};


const generateToken = async (userId) => {
    const secret = JWT_SECRET
    const accessTokenExpires = moment().add(
        JWT_ACCESS_EXPIRATION_MINUTES,
        "minutes"
    );

    const payload = {
        sub: await encryptUserID(userId),
        iat: moment().unix(),
        exp: accessTokenExpires.unix(),
    };
    return jwt.sign(payload, secret);
};

const generateRefreshToken = async (userId) => {
    const secret = JWT_REFRESH_SECRET
    const accessTokenExpires = moment().add(
        JWT_REFRESH_EXPIRATION_DAYS,
        "days"
    );

    const payload = {
        sub: await encryptUserID(userId),
        iat: moment().unix(),
        exp: accessTokenExpires.unix(),
    };
    return jwt.sign(payload, secret);
};

const verifyToken = async (token, refreshToken = false) => {
    const key = refreshToken ? JWT_REFRESH_SECRET : JWT_SECRET

    const payload = jwt.verify(token, key);
    const userId = await decryptUserID(payload.sub);

    return userId;
};

module.exports = { generateToken, generateRefreshToken, verifyToken }
