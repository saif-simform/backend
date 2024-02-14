const express = require('express')
const cors = require('cors')
const httpStatus = require('http-status')
const cookieParser = require('cookie-parser')
const { generateToken, verifyToken } = require('./token.service')
const { CurrentUser, Posts } = require('./constant')
const { isAuthenticated } = require('./authentication')
require('dotenv').config()


//Initiate the app
const app = express()
app.use(express.json({ limit: "100mb" }));
app.use(cookieParser())

//CORS
app.use(cors())


//Define login route
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    const user = CurrentUser.find(u => u.email === email && u.password === password)

    if (!user) {
        return res.status(httpStatus.NOT_FOUND).send({ message: 'Invalid email or password' })
    }

    const token = await generateToken(user.id)
    const refreshToken = await generateToken(user.id, true)
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

    const userInstance = await verifyToken(refreshToken, true);

    if (!userInstance) {
        return res.status(httpStatus.UNAUTHORIZED).send({ message: 'Invalid token' })
    }

    const token = await generateToken(userInstance.id)

    return res.status(httpStatus.OK).send({
        accessToken: token,
        success: true
    })

})

//Define get post route
app.get('/api/posts', isAuthenticated(), async (req, res) => {

    try {

        return res.status(httpStatus.OK).send({
            data: Posts,
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
