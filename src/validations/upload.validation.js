const Joi = require('joi');

const uploadFile = {
  body: Joi.object().keys({}),
};

module.exports = {
  uploadFile,
};
