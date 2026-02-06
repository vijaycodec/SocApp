import mongoose from 'mongoose';

const sopSchema = new mongoose.Schema({
  sop_name: {
    type: String,
    required: [true, 'SOP name is required'],
    trim: true,
    minlength: [3, 'SOP name must be at least 3 characters'],
    maxlength: [200, 'SOP name cannot exceed 200 characters']
  },
  title: {
    type: String,
    required: [true, 'Title is required'],
    trim: true,
    minlength: [3, 'Title must be at least 3 characters'],
    maxlength: [300, 'Title cannot exceed 300 characters']
  },
  description: {
    type: String,
    required: [true, 'Description is required'],
    trim: true
  },

  // File Information (for generated reports)
  file_path: {
    type: String,
    trim: true,
    default: null
  },
  file_name: {
    type: String,
    trim: true,
    default: null
  },
  file_size: {
    type: Number,
    min: [0, 'File size cannot be negative'],
    default: null
  },
  report_generated_at: {
    type: Date,
    default: null
  },

  // Status
  status: {
    type: String,
    enum: ['draft', 'published', 'archived'],
    default: 'draft'
  },

  // Relationships
  created_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: [true, 'Created by user ID is required']
  },
  updated_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },

  // Soft Delete
  is_deleted: {
    type: Boolean,
    default: false,
    index: true
  },
  deleted_at: {
    type: Date,
    default: null
  },
  deleted_by: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
sopSchema.index({ created_by: 1, is_deleted: 1 });
sopSchema.index({ status: 1 });
sopSchema.index({ createdAt: -1 });

// Pre-save middleware
sopSchema.pre('save', function(next) {
  if (this.is_deleted && !this.deleted_at) {
    this.deleted_at = new Date();
  }
  if (!this.is_deleted && this.deleted_at) {
    this.deleted_at = null;
    this.deleted_by = null;
  }
  next();
});

// Static method to find non-deleted SOPs
sopSchema.statics.findActive = function(filter = {}) {
  return this.find({ ...filter, is_deleted: false });
};

// Instance method for soft delete
sopSchema.methods.softDelete = async function(deletedBy) {
  this.is_deleted = true;
  this.deleted_at = new Date();
  this.deleted_by = deletedBy;
  return await this.save();
};

const Sop = mongoose.model('Sop', sopSchema);
export default Sop;
