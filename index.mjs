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

app.use(express.static('docs'))

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

/**
 * @api {get} /me Afficher l'utilisateur connecté
 * @apiHeader Authorization Basic Access Authentication token
 * @apiName GetMe
 * @apiGroup Users
 * @apiSampleRequest me
 */
app.get('/me', verifyToken, async (req, res) => {
  const token = req.headers.authorization.substring(7)
  const decoded = jwt.verify(token, process.env.SECRET)
  res.json({
    id: decoded.id,
    email: decoded.email,
    name: decoded.name
  })
})

/**
 * @api {post} /user Créer un utilisateur
 * @apiName PostUser
 * @apiGroup Users
 * @apiHeader Content-Type=application/json application/json
 * @apiExample Example usage:
 *     body:
 *     {
 *       "email": "user@email.com",
 *       "name": "User name",
 *       "password": "szjkdjklkjdz"
 *     }
 * @apiParam (body/json) {String} email User email
 * @apiParam (body/json) {String} name User name
 * @apiParam (body/json) {String} password User password
 * @apiSampleRequest user
 */
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

/**
 * @api {post} /login Se connecter
 * @apiName PostLogin
 * @apiGroup Users
 * @apiHeader Content-Type=application/json application/json
 * @apiExample Example usage:
 *     body:
 *     {
 *       "email": "user@email.com",
 *       "password": "szjkdjklkjdz"
 *     }
 * @apiParam (body/json) {String} email User email
 * @apiParam (body/json) {String} password User password
 * @apiSampleRequest login
 */
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
    res.status(401)
    res.json({
      error: "Identifiant invalid"
    })
  }
})


app.get('*', (req, res) => {
  res.status(404)
  res.send("The requested URL was not found on the server.")
})

app.listen(3000, () => {
  console.log('Server run at http://localhost:3000')
})
