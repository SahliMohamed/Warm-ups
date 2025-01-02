// Load Environment Variables
require('dotenv').config()

// Initialize express app
const express = require('express')
const app = express()

// middleware
app.use((req, res, next) => {
    console.log(req.path, req.method)
    next()
})
// routes
app.get('/', (req, res) =>{
    res.json({mssg: 'hello word'})
})

// listen for requests
app.listen(process.env.PORT, () => {
    console.log('listening on port',process.env.PORT)
})

