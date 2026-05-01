const httpStatus = require('http-status');
const { scanBytes, STRICT_PUBLIC_UPLOAD } = require('pompelmi');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');

const SCAN_TIMEOUT_MS = 5000;

const scanBytesWithTimeout = async (buffer, options) => {
  let timeoutId;

  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error('Scan timeout'));
    }, SCAN_TIMEOUT_MS);
  });

  try {
    return await Promise.race([scanBytes(buffer, options), timeoutPromise]);
  } finally {
    clearTimeout(timeoutId);
  }
};

const uploadFile = catchAsync(async (req, res) => {
  if (!req.file) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'No file uploaded');
  }

  let report;

  try {
    report = await scanBytesWithTimeout(req.file.buffer, {
      filename: req.file.originalname,
      mimeType: req.file.mimetype,
      policy: STRICT_PUBLIC_UPLOAD,
      failClosed: true,
    });
  } catch (err) {
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, 'Upload blocked: scan could not complete');
  }

  if (report.verdict === 'ScanError') {
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, 'Upload blocked: scan could not complete');
  }

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
