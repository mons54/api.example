import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import mongoose from 'mongoose'
import bcryptjs from 'bcryptjs'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'

dotenv.config()

mongoose.connect('mongodb://localhost/api-example', {
  useCreateIndex: true,
  useNewUrlParser: true
})

const db = mongoose.connection

db.on('error', console.log)
db.once('open', () => {
  console.log('mongodb is connected')
})

const userSchema = new mongoose.Schema({
  name: String,
  email: {
    unique: true,
    type: String,
  },
  password: String
})

const user = mongoose.model('user', userSchema)

const app = express()

app.use(cors({
  origin: '*'
}))

app.use(bodyParser.json())

function verifyToken (req, res, next) {
  let token = req.headers.authorization
  if (typeof token === 'string' &&
      token.startsWith('Bearer ')) {
    token = token.substring(7)
    try {
      jwt.verify(token, process.env.SECRET)
      return next()
    } catch (e) {
      res.status(401)
      res.json({
        error: "Invalid Access Token"
      })
    }
  } else {
    res.status(401)
    res.json({
      error: "Access Token is required"
    })
  }
}

app.get('/me', verifyToken, (req, res) => {
  res.send('Prend moi !')
})

app.post('/user', async (req, res) => {
  const email = req.body.email
  const password = req.body.password
  const name = req.body.name

  const hash = bcryptjs.hashSync(password)

  const newUser = new user({
    email,
    password: hash,
    name,
  })

  try {
    const data = (await newUser.save()).toObject()
    delete data.password
    res.json(data)
  } catch (e) {
    res.status(401)
    res.json({
      error: e.errmsg
    })
  }
})

app.post('/login', async (req, res) => {
  const email = req.body.email
  const password = req.body.password

  const data = await user.findOne({
    email
  })

  if (bcryptjs.compareSync(password, data.password)) {
    const token = jwt.sign({
      id: data._id,
      name: data.name,
      email: data.email,
    }, process.env.SECRET, {
      expiresIn: 86400 // 60 * 60 * 24
    })

    res.json({
      token
    })

  } else {

  }
  console.log(data)
})


app.get('*', (req, res) => {
  res.status(404)
  res.send("The requested URL was not found on the server.")
})

app.listen(3000, () => {
  console.log('Server run at http://localhost:3000')
})
