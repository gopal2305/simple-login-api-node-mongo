const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const ip = require('ip');
const User = db.User;

module.exports = {
    authenticate,
    getAll,
    getAuditUsers,
    getById,
    create,
    update,
    logout,
    delete: _delete
};

async function authenticate({ username, password, role }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash) && user.role == role) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id, role: user.role }, config.secret);
        user.loginTime = new Date();
        user.clientIP = ip.address();
        user.save();
        return {
            ...userWithoutHash,
            token,
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getAuditUsers() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);
    user.role = userParam.role.toLowerCase();
    user.clientIP = ip.address();
    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function logout(userParam) {
    const user = await User.findOne({ username: userParam.username });
    user.logoutTime = new Date();
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);
    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}