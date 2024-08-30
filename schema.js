const mongoose = require("mongoose");

const schema = new mongoose.Schema({
    name: {
        type: String,
    },
    registerNo: {
        type: String,
    },
    gender: {
        type: String,
    },
    graduate: {
        type: String,
    },
    hsc: {
        type: String,
    },
    myambition: {
        type: String,
    },
    dept: {
        type: String,
    },
    dob: {
        type: String,
    },
    date: {
        type: String,
    },
    arr: [{}], // Example array type
    lastUpdated: {
        type: Date,
        default: Date.now
    }
});

const model = mongoose.model("model", schema);

module.exports = { model };
