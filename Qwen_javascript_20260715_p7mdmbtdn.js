const mongoose = require('mongoose');

const chatSchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    sessionId: { type: String, required: true },
    title: { type: String, default: 'New Chat' },
    messages: [{
        role: { type: String, enum: ['user', 'assistant'], required: true },
        content: { type: String, required: true },
        timestamp: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

chatSchema.index({ userId: 1, updatedAt: -1 });

module.exports = mongoose.model('Chat', chatSchema);