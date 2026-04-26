const express = require('express');
const multer = require('multer');
const httpStatus = require('http-status');
const auth = require('../../middlewares/auth');
const ApiError = require('../../utils/ApiError');
const validate = require('../../middlewares/validate');
const uploadValidation = require('../../validations/upload.validation');
const uploadController = require('../../controllers/upload.controller');

const router = express.Router();

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new ApiError(httpStatus.BAD_REQUEST, 'Invalid file type'), false);
    }
  },
});

router.route('/').post(auth(), upload.single('file'), validate(uploadValidation.uploadFile), uploadController.uploadFile);

module.exports = router;
