// userModel.js file
import User from '../models/userModel.js';

export const findUserById = async (userId) => {
    try {
        const user = await User.findById(userId);
        return user;
    } catch (error) {
        throw new Error('Error finding user by ID');
    }
};