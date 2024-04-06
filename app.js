require('dotenv').config();
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const User = require("./models/User")

const app = express();
app.use(express.json());


app.get('/', (req, res) => {
    res.status(200).json({ msg: "API Funcionando" })
})

app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id
    const user = await User.findById(id, '-password')
    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" })
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['autorizathion']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).json({ msg: "Acesso Negado!" })
    }

    try {

        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({ msg: "Token Inválido" })
    }
};

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return re.test(email)
};


app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpassword } = req.body
    if (!name) {
        return res.status(422).json({ msg: "Nome é obrigatório" })
    }
    if (!email) {
        return res.status(422).json({ msg: "E-mail é obrigatório" })
    }
    if (!validateEmail(email)) {
        return res.status(422).json({ msg: "E-mail inválido" })
    }
    if (!password) {
        return res.status(422).json({ msg: "Senha é obrigatório" })
    }
    if (password !== confirmpassword) {
        return res.status(422).json({ msg: "As senhas não conferem" })
    }
    const userExist = await User.findOne({ email: email })
    if (userExist) {
        return res.status(422).json({ msg: "E-mail já Cadastrado, utilize outro e-mail" })
    }
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(200).json({ msg: "Usuário Cadastrado com Sucesso!" })
    } catch (error) {
        console.log(error)
        return res.status(500).json({ msg: "Aconteceu um erro interno, tente novamente mais tarde!!" })
    }
})

app.post('/auth/user', async (req, res) => {

    const { email, password } = req.body
    if (!email) {
        return res.status(422).json({ msg: "E-mail é obrigatório" })
    }
    if (!password) {
        return res.status(422).json({ msg: "Senha é obrigatório" })
    }
    const user = await User.findOne({ email: email })
    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado" })
    }
    const checkPassword = await bcrypt.compare(password, user.password)
    if (!checkPassword) {
        return res.status(422).json({ msg: "Senha Inválida!" })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id
        },
            secret,
        )

        res.status(200).json({ msg: "Autenticação realizada com sucesso", token })
    } catch (error) {
        console.log(error)
        res.status(402).json({ msg: "Aconteceu um erro interno, tente novamente mais tarde!!" })
    }

})



const dbuser = process.env.DB_USER
const dbpass = process.env.DB_PASSWORD

mongoose.connect(`mongodb+srv://${dbuser}:${dbpass}@apifinanceiro.zyes2qy.mongodb.net/?retryWrites=true&w=majority&appName=APIFinanceiro`)
    .then(() => {
        app.listen(3000)
        console.log("Conectado ao Banco")
    }).catch((err) => console.log(err));