const httpStatus = require('http-status');
const { scanBytes, STRICT_PUBLIC_UPLOAD } = require('pompelmi');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');

const uploadFile = catchAsync(async (req, res) => {
  if (!req.file) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'No file uploaded');
  }

  const report = await scanBytes(req.file.buffer, {
    filename: req.file.originalname,
    mimeType: req.file.mimetype,
    policy: STRICT_PUBLIC_UPLOAD,
    failClosed: true,
  });

  if (report.verdict !== 'clean') {
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, `Upload blocked: ${report.reasons.join(', ')}`);
  }

  res.status(httpStatus.OK).send({
    message: 'File accepted',
    filename: req.file.originalname,
  });
});

module.exports = {
  uploadFile,
};
