const httpStatus = require("http-status")
const { verifyToken } = require("./token.service")

const isAuthenticated = () => {
    return async (req, res, next) => {
        try {
            let token = req.headers.authorization || req.query.headers.authorization

            if (!token) {
                return res.status(httpStatus.UNAUTHORIZED).send({ message: "Unauthorized access", success: false })
            }

            token = token.split(" ")
            if (!["Bearer", "Token"].includes(token[0])) {
                return res
                    .status(httpStatus.UNAUTHORIZED)
                    .send({ message: "Invalid token", success: false });
            }

            const userInstance = await verifyToken(token[1]);

            if (!userInstance) {
                return res.status(httpStatus.UNAUTHORIZED).send({ message: 'Token expire' })
            }
            req.user = userInstance;
            next()
        } catch (err) {
            return res.status(httpStatus.UNAUTHORIZED).send({
                message: "Error name: " + err.name + "Error message: " + err.message,
                success: false,
            })
        }
    }
}

module.exports = { isAuthenticated }