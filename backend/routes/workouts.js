const express = require('express')

// controller functions
const {
    createWorkout,
    getWorkouts,
    getWorkout,
    deleteWorkout,
    updateWorkout
} = require('../controllers/workoutController')
const requireAuth = require('../middleware/requireAuth')

const router = express.Router()

// require auth for all workout routes
router.use(requireAuth)

// GET all workouts'
router.get('/', getWorkouts)

//GET a single workout'
router.get('/:id',getWorkout)
    
// POST new workout
router.post('/',createWorkout)

// DELETE workout
router.delete('/:id', deleteWorkout)

// UPDATE a workout
router.patch('/:id', updateWorkout)
module.exports = router