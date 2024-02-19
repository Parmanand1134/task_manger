import jwt from 'jsonwebtoken';
import { findUserById } from '../controllers/index.js';

export const verifyTokenMiddleware = async (req, res, next) => {
    try {
        let token = req.body.token || req.query.token || req.headers["x-access-token"] || req.headers["authorization"];
        if (!token) {
            return res.status(403).send({ status: 'Failed', message: "A token is required for authentication", data: '' });
        }
        token = token.replace("Bearer ", "");
        const temp = jwt.verify(token, "mysecretkeyyyyyyyyyyyyyyyy");
        req.decoded = temp;
        const findData = await findUserById(req.decoded._id);
        if (findData) {
            return next();
        } else {
            throw { status: 401, message: 'UNAUTHORIZED' };
        }
    } catch (err) {
        if (err.status === 401) {
            return res.status(401).send({ status: 'Failed', message: err.message, data: '' });
        } else {
            return res.status(400).send({ statusCode: 0, message: err.toString() });
        }
    }
};
