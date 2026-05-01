const httpStatus = require('http-status');
const { scanBytes, STRICT_PUBLIC_UPLOAD } = require('pompelmi');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');

const SCAN_TIMEOUT_MS = 5000; // 5 seconds

const scanWithTimeout = (buffer, options) => {
  return Promise.race([
    scanBytes(buffer, options),
    new Promise((_, reject) => setTimeout(() => reject(new Error('Scan timeout')), SCAN_TIMEOUT_MS)),
  ]);
};

const uploadFile = catchAsync(async (req, res) => {
  if (!req.file) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'No file uploaded');
  }

  let report;
  try {
    report = await scanWithTimeout(req.file.buffer, {
      filename: req.file.originalname,
      mimeType: req.file.mimetype,
      policy: STRICT_PUBLIC_UPLOAD,
      failClosed: true,
    });
  } catch (err) {
    // timeout or scan error — fail closed
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, `Upload blocked: scan error — ${err.message}`);
  }

  if (report.verdict === 'malicious' || report.verdict === 'suspicious') {
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, `Upload blocked: ${report.reasons.join(', ')}`);
  }

  if (report.verdict !== 'clean') {
    // handles ScanError or any unexpected verdict — fail closed
    throw new ApiError(httpStatus.UNPROCESSABLE_ENTITY, 'Upload blocked: scan could not complete');
  }

  res.status(httpStatus.OK).send({
    message: 'File accepted',
    filename: req.file.originalname,
  });
});

module.exports = {
  uploadFile,
};
