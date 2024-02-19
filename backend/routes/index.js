import express from 'express';
import joi from 'joi';
import mongoose from 'mongoose';
import Project from '../models/index.js'
import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { verifyTokenMiddleware } from '../helper/auth.js';
import Role from '../models/roleModel.js';
const api = express.Router()

api.get('/projects', verifyTokenMiddleware, async (req, res) => {
    try {
        const data = await Project.find({}, { task: 0, __v: 0, updatedAt: 0 }).sort({ createdAt: -1 });
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }
})

api.get('/project/:id', verifyTokenMiddleware, async (req, res) => {
    if (!req.params.id) res.status(422).send({ data: { error: true, message: 'Id is reaquire' } })
    try {
        const data = await Project.find({ _id: mongoose.Types.ObjectId(req.params.id) }).sort({ order: 1 })
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }
})

api.post('/project', verifyTokenMiddleware, async (req, res) => {

    // validate type 
    const project = joi.object({
        title: joi.string().min(3).max(30).required(),
        description: joi.string().required(),
    })

    // validation
    const { error, value } = project.validate({ title: req.body.title, description: req.body.description });
    if (error) return res.status(422).send(error)


    // insert data 
    try {
        const data = await new Project(value).save()
        res.send({ data: { title: data.title, description: data.description, updatedAt: data.updatedAt, _id: data._id } })

    } catch (e) {
        if (e.code === 11000) {
            return res.status(422).send({ data: { error: true, message: 'title must be unique' } })
        } else {
            return res.status(500).send({ data: { error: true, message: 'server error' } })
        }
    }


})

api.put('/project/:id', verifyTokenMiddleware, async (req, res) => {
    // validate type 
    const project = joi.object({
        title: joi.string().min(3).max(30).required(),
        description: joi.string().required(),
    })

    // // validation
    const { error, value } = project.validate({ title: req.body.title, description: req.body.description });
    if (error) return res.status(422).send(error)

    Project.updateOne({ _id: mongoose.Types.ObjectId(req.params.id) }, { ...value }, { upsert: true }, (error, data) => {
        if (error) {
            res.send(error)
        } else {
            res.send(data)
        }
    })


})

api.delete('/project/:id', verifyTokenMiddleware, async (req, res) => {
    try {
        const data = await Project.deleteOne({ _id: mongoose.Types.ObjectId(req.params.id) })
        res.send(data)
    } catch (error) {
        res.send(error)
    }

})


//  task api   

api.post('/project/:id/task', verifyTokenMiddleware, async (req, res) => {


    if (!req.params.id) return res.status(500).send(`server error`);

    // validate type 
    const task = joi.object({
        title: joi.string().min(3).max(30).required(),
        description: joi.string().required(),
    })

    const { error, value } = task.validate({ title: req.body.title, description: req.body.description });
    if (error) return res.status(422).send(error)

    try {
        // const task = await Project.find({ _id: mongoose.Types.ObjectId(req.params.id) }, { "task.index": 1 })
        const [{ task }] = await Project.find({ _id: mongoose.Types.ObjectId(req.params.id) }, { "task.index": 1 }).sort({ 'task.index': 1 })


        let countTaskLength = [task.length, task.length > 0 ? Math.max(...task.map(o => o.index)) : task.length];

        const data = await Project.updateOne({ _id: mongoose.Types.ObjectId(req.params.id) }, { $push: { task: { ...value, stage: "Requested", order: countTaskLength[0], index: countTaskLength[1] + 1 } } })
        return res.send(data)
    } catch (error) {
        return res.status(500).send(error)
    }
})

api.get('/project/:id/task/:taskId', verifyTokenMiddleware, async (req, res) => {

    if (!req.params.id || !req.params.taskId) return res.status(500).send(`server error`);

    // res.send(req.params)
    try {

        let data = await Project.find(
            { _id: mongoose.Types.ObjectId(req.params.id) },
            {
                task: {
                    $filter: {
                        input: "$task",
                        as: "task",
                        cond: {
                            $in: [
                                "$$task._id",
                                [
                                    mongoose.Types.ObjectId(req.params.taskId)
                                ]
                            ]
                        }
                    }
                }
            })
        if (data[0].task.length < 1) return res.status(404).send({ error: true, message: 'record not found' })
        return res.send(data)
    } catch (error) {
        return res.status(5000).send(error)
    }


})


api.put('/project/:id/task/:taskId', verifyTokenMiddleware, async (req, res) => {

    if (!req.params.id || !req.params.taskId) return res.status(500).send(`server error`);

    const task = joi.object({
        title: joi.string().min(3).max(30).required(),
        description: joi.string().required(),
    })

    const { error, value } = task.validate({ title: req.body.title, description: req.body.description });
    if (error) return res.status(422).send(error)

    try {
        // const data = await Project.find({ $and: [{ _id: mongoose.Types.ObjectId(req.params.id) }, { "task._id": mongoose.Types.ObjectId(req.params.taskId) }] },{
        //     task: {
        //         $filter: {
        //             input: "$task",
        //             as: "task",
        //             cond: {
        //                 $in: [
        //                     "$$task._id",
        //                     [
        //                         mongoose.Types.ObjectId(req.params.taskId)
        //                     ]
        //                 ]
        //             }
        //         }
        //     }
        // })
        const data = await Project.updateOne({
            _id: mongoose.Types.ObjectId(req.params.id),
            task: { $elemMatch: { _id: mongoose.Types.ObjectId(req.params.taskId) } }
        }, { $set: { "task.$.title": value.title, "task.$.description": value.description } })
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }

})

api.delete('/project/:id/task/:taskId', verifyTokenMiddleware, async (req, res) => {

    if (!req.params.id || !req.params.taskId) return res.status(500).send(`server error`);

    try {
        const data = await Project.updateOne({ _id: mongoose.Types.ObjectId(req.params.id) }, { $pull: { task: { _id: mongoose.Types.ObjectId(req.params.taskId) } } })
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }

})

api.put('/project/:id/todo', verifyTokenMiddleware, async (req, res) => {
    let todo = []

    for (const key in req.body) {
        // todo.push({ items: req.body[key].items, name: req.body[key]?.name })
        for (const index in req.body[key].items) {
            req.body[key].items[index].stage = req.body[key].name
            todo.push({ name: req.body[key].items[index]._id, stage: req.body[key].items[index].stage, order: index })
        }
    }

    todo.map(async (item) => {
        await Project.updateOne({
            _id: mongoose.Types.ObjectId(req.params.id),
            task: { $elemMatch: { _id: mongoose.Types.ObjectId(item.name) } }
        }, { $set: { "task.$.order": item.order, "task.$.stage": item.stage } })
    })

    res.send(todo)
})


// User registration endpoint
api.post('/register', async (req, res) => {
    // Validate request body
    const schema = joi.object({
        username: joi.string().required(),
        email: joi.string().email().required(),
        password: joi.string().min(6).required(),
        role: joi.string()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    try {
        // Check if the email is already registered
        const existingUser = await User.findOne({ email: value.email });
        if (existingUser) return res.status(400).send('Email already exists');

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(value.password, salt);
        const findRole = await Role.findOne({ name: value.role });
        // Create a new user
        const newUser = new User({
            username: value.username,
            email: value.email,
            password: hashedPassword,
            role: findRole._id
        });
        const data = await newUser.save();

        res.status(201).send({ status: 1, message: 'User registered successfully', data: data });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// User login endpoint
api.post('/login', async (req, res) => {
    // Validate request body
    const schema = joi.object({
        email: joi.string().email().required(),
        password: joi.string().required()
    });
    const { error, value } = schema.validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    try {
        // Check if the user exists
        const user = await User.findOne({ email: value.email });
        if (!user) return res.status(400).send('Invalid email or password');

        // Verify the password
        const validPassword = await bcrypt.compare(value.password, user.password);
        if (!validPassword) return res.status(400).send('Invalid email or password');

        // Generate JWT token
        const token = jwt.sign({ _id: user._id, email: user.email }, "mysecretkeyyyyyyyyyyyyyyyy");
        res.status(200).send({ status: 1, message: 'User Login successfully', data: user, token: token });

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

api.get('/role', async (req, res) => {
    try {
        const data = await Role.find()
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }
})

api.get('/users', async (req, res) => {
    try {
        const data = await User.find()
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }
})

api.get('/assignTask', async (req, res) => {
    try {
        const data = await User.find()
        return res.send(data)
    } catch (error) {
        return res.send(error)
    }
})

export default api