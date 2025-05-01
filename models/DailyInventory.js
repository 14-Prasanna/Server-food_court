const mongoose = require('mongoose');

const dailyInventorySchema = new mongoose.Schema({
  menuItemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: true },
  date: { type: Date, required: true, default: Date.now }, // Date for the inventory entry
  quantity: { type: Number, default: 0 }, // Daily quantity
});

const DailyInventory = mongoose.model('DailyInventory', dailyInventorySchema);
module.exports = DailyInventory;