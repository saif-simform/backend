const express = require('express')
const cors = require('cors')
const httpStatus = require('http-status')
const cookieParser = require('cookie-parser')
const { generateToken, decryptUserID, verifyToken, generateRefreshToken } = require('./token.service')
require('dotenv').config()


//Initiate the app
const app = express()
app.use(express.json({ limit: "100mb" }));
app.use(cookieParser())

//CORS
app.use(cors())

//Dummy user credentials
const currentUser = [{
    id: 1, email: "pathansaifuddin@gmail.com", password: "123123"
}, {
    id: 2, email: "abc@abc.com", password: "123123"
}]

//Dummy data for posts
const posts = [
    { id: 1, title: 'Post 1', content: 'Use Simform React CLI' },
    { id: 2, title: 'Post 2', content: 'Create React project with Readux and Axios' },
    { id: 3, title: 'Post 3', content: 'Test the CLI features' }
];

//Define login route
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    const user = currentUser.find(u => u.email === email && u.password === password)

    if (!user) {
        return res.status(httpStatus.NOT_FOUND).send({ message: 'Invalid email or password' })
    }

    const token = await generateToken(user.id)
    const refreshToken = await generateRefreshToken(user.id)
    // res.set('Access-Control-Expose-Headers', 'Set-Cookie');
    // res.type('application/json');
    // res.setHeader('Content-Type', 'application/json');
    res.status(httpStatus.OK).send({
        accessToken: token,
        refreshToken: refreshToken,
        message: 'login success',
        success: true
    })
})

//Define refresh-token route
app.post('/auth/refresh-token', async (req, res) => {
    const { refreshToken } = req.body

    if (!refreshToken) {
        return res.status(httpStatus.BAD_REQUEST).send({ message: 'Refresh token is required!' })
    }

    const userId = await verifyToken(refreshToken, true);
    const userInstance = currentUser.find(u => u.id == userId)

    if (!userInstance) {
        return res.status(httpStatus.UNAUTHORIZED).send({ message: 'Invalid token' })
    }

    const token = await generateToken(userId)

    return res.status(httpStatus.OK).send({
        accessToken: token,
        success: true
    })

})

//Define get post route
app.get('/api/posts', async (req, res) => {

    try {

        let token = req.headers.authorization || req.query.authorization;

        if (!token) {
            return res.status(httpStatus.UNAUTHORIZED).send({ message: "Unauthorized access", success: false })
        }

        token = token.split(" ");
        if (!["Bearer", "Token"].includes(token[0])) {
            return res
                .status(httpStatus.UNAUTHORIZED)
                .send({ message: "Invalid token", success: false });
        }

        const userId = await verifyToken(token[1]);
        const userInstance = currentUser.find(user => user.id == userId)

        if (!userInstance) {
            return res.status(httpStatus.UNAUTHORIZED).send({ message: 'Invalid token' })
        }

        return res.status(httpStatus.OK).send({
            data: posts,
            success: true
        })
    } catch (err) {

        return res.status(httpStatus.UNAUTHORIZED).send({
            message: "Error name: " + err.name + "Error message: " + err.message,
            success: false,
        })
    }
})

//Start the server 
const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`)
})
